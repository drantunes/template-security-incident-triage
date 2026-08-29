import { readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

// Narrow, reproducible patch for @mastra/redis-streams 0.4.0. Mastra still
// owns RedisStreamsPubSub directly; this closes its PEL/durability boundaries.
// Tests use an isolated package tree; production postinstall deliberately
// keeps resolving from this package. The override is not a configuration
// surface for the adapter itself.
const root = resolve(
  process.env.PHASE8_REDIS_STREAMS_PATCH_ROOT ??
    resolve(import.meta.dirname, ".."),
);
const runtimePath = resolve(
  root,
  "node_modules/@mastra/redis-streams/dist/index.js",
);
const typesPath = resolve(
  root,
  "node_modules/@mastra/redis-streams/dist/index.d.ts",
);
const marker = "phase8-redis-retention-tombstone-v6";
const previousMarker = "phase8-redis-retention-tombstone-v5";
const olderMarker = "phase8-redis-retention-tombstone-v4";
const legacyMarker = "phase8-redis-retention-tombstone-v3";
const oldestMarker = "phase8-redis-retention-tombstone-v2";
const runtime = await readFile(runtimePath, "utf8");
const types = await readFile(typesPath, "utf8");
const typeNeedle = "    logger?: {\n";
const retainDeliveryCatch = `\t\ttry {
\t\t\tawait sub.cb(event, ack, nack);
\t\t} catch (err) {
\t\t\t// Local poison persistence is a durable boundary: retaining the PEL
\t\t\t// entry is the only safe result until its transaction commits.
\t\t\tif (err && typeof err === "object" && err.code === "PHASE8_RETAIN_DELIVERY") {
\t\t\t\tthis.#logger?.warn?.("redis-streams: retaining delivery after local durability failure", { topic: sub.topic, streamId });
\t\t\t\treturn;
\t\t\t}
\t\t\tawait nack();
\t\t}`;
const retainTombstoneHookFailure = `\t\t\t\ttry {
\t\t\t\t\tawait this.#claimDeletedHook({ topic: item.topic, streamId: item.streamId, group: item.group, consumer: item.consumer, errorCode: "STREAM_ENTRY_TRIMMED" });
\t\t\t\t\tawait this.#writeClient.xDel(key, entry.id);
\t\t\t\t} catch (hookErr) {
\t\t\t\t\t// Keep this tombstone pending, but never let one failed audit
\t\t\t\t\t// terminate XREADGROUP for all later entries.
\t\t\t\t\tthis.#logger?.warn?.("redis-streams: tombstone audit retry pending", { topic: item.topic, streamId: item.streamId, err: errorText(hookErr) });
\t\t\t\t}`;
const typeDeclarations = `    /** Called and awaited for raw decode poison before XACK. Raw bytes are transient. */
    onDecodeFailure?: (input: { topic: string; streamId: string; group: string; consumer: string; pel: { pending: true; deliveryCount?: number }; rawBytes: Uint8Array; errorCode: "EVENT_INVALID" }) => Promise<void>;
    /** Receives durable Redis tombstones until local persistence succeeds. */
    onClaimDeleted?: (input: { topic: string; streamId: string; group: string; consumer: string; errorCode: "STREAM_ENTRY_TRIMMED" }) => Promise<void>;
`;
const canonicalTypeDeclarations = (input) =>
  input
    // A crash can leave either declaration (or an older signature) behind.
    // Remove both independently, then install the exact v6 pair once.
    .replace(
      /\x20{4}\/\*\* Called and awaited for raw decode poison before XACK\. Raw bytes are transient\. \*\/\n\x20{4}onDecodeFailure\?:[^\n]*\n/g,
      "",
    )
    .replace(
      /\x20{4}\/\*\* Receives durable Redis tombstones until local persistence succeeds\. \*\/\n\x20{4}onClaimDeleted\?:[^\n]*\n/g,
      "",
    )
    .replace(/\x20{4}onDecodeFailure\?:[^\n]*\n/g, "")
    .replace(/\x20{4}onClaimDeleted\?:[^\n]*\n/g, "")
    .replace(typeNeedle, `${typeDeclarations}${typeNeedle}`);

const retentionMethod = `\tasync #maintainStreamRetention(streamKey) {
\t\tif (this.#maxStreamLength <= 0) return;
\t\tconst groups = await this.#writeClient.sendCommand(["XINFO", "GROUPS", streamKey]);
\t\tlet safeCutoff;
\t\tlet allGroupsCaughtUp = true;
\t\tconst addCutoff = (streamId) => {
\t\t\tif (!safeCutoff || this.#streamIdBefore(streamId, safeCutoff)) safeCutoff = streamId;
\t\t};
\t\tfor (const fields of groups ?? []) {
\t\t\tconst field = (key) => {
\t\t\t\tif (!Array.isArray(fields)) return fields?.[key];
\t\t\t\tconst index = fields.indexOf(key);
\t\t\t\treturn index < 0 ? undefined : fields[index + 1];
\t\t\t};
\t\t\tconst name = field("name");
\t\t\tconst lagRaw = field("lag");
\t\t\tconst lastDelivered = field("last-delivered-id");
\t\t\t// A missing/invalid group frontier is not evidence that its unread
\t\t\t// entries are disposable. In particular, 0-0 means no entry was ever
\t\t\t// delivered, so there is no lower safe MINID boundary.
\t\t\tif (typeof name !== "string" || lagRaw === undefined || lagRaw === null || !this.#isStreamId(lastDelivered) || lastDelivered === "0-0") return;
\t\t\tconst lag = Number(lagRaw);
\t\t\tif (!Number.isSafeInteger(lag) || lag < 0) return;
\t\t\tconst pending = await this.#writeClient.sendCommand(["XPENDING", streamKey, name]);
\t\t\tconst count = Number(Array.isArray(pending) ? pending[0] : pending?.count);
\t\t\tconst first = Array.isArray(pending) ? pending[1] : pending?.minId;
\t\t\tif (!Number.isSafeInteger(count) || count < 0) return;
\t\t\tif (count > 0) {
\t\t\t\tif (!this.#isStreamId(first)) return;
\t\t\t\tallGroupsCaughtUp = false;
\t\t\t\taddCutoff(first);
\t\t\t}
\t\t\tif (lag > 0) {
\t\t\t\tallGroupsCaughtUp = false;
\t\t\t\t// An unread entry is strictly after lastDelivered. Retaining that
\t\t\t\t// ID is conservative and composes safely with every group's PEL.
\t\t\t\taddCutoff(lastDelivered);
\t\t\t}
\t\t}
\t\tif (safeCutoff) await this.#writeClient.sendCommand(["XTRIM", streamKey, "MINID", "~", safeCutoff]);
\t\telse if (allGroupsCaughtUp) await this.#writeClient.sendCommand(["XTRIM", streamKey, "MAXLEN", "~", String(this.#maxStreamLength)]);
\t}`;

const streamIdHelpers = `\t#streamIdBefore(left, right) {
\t\tconst [leftMs, leftSeq] = left.split("-").map(BigInt);
\t\tconst [rightMs, rightSeq] = right.split("-").map(BigInt);
\t\treturn leftMs < rightMs || (leftMs === rightMs && leftSeq < rightSeq);
\t}
\t#isStreamId(value) {
\t\treturn typeof value === "string" && /^\\d+-\\d+$/.test(value);
\t}`;

const requireReplacement = (changed, label) => {
  if (!changed)
    throw new Error(`Redis Streams 0.4.0 patch did not match ${label}.`);
};

async function writeAtomically(path, contents) {
  const staged = `${path}.phase8-${process.pid}-${Date.now()}.tmp`;
  await writeFile(staged, contents, "utf8");
  await rename(staged, path);
}

// Every supported predecessor is first reduced to the 0.4.0-shaped source and
// then receives the *same* v6 transform as a clean install. A marker is only a
// hint about what may need normalising; it is never proof that v6 semantics are
// present. This prevents a partial v3/v4/v5 upgrade from becoming a permanent
// no-op after merely changing its marker.
let source = runtime
  .replaceAll(`\t// ${marker}\n`, "")
  .replaceAll(`\t// ${previousMarker}\n`, "")
  .replaceAll(`\t// ${olderMarker}\n`, "")
  .replaceAll(`\t// ${legacyMarker}\n`, "")
  .replaceAll(`\t// ${oldestMarker}\n`, "")
  .replaceAll(marker, "")
  .replaceAll(previousMarker, "")
  .replaceAll(olderMarker, "")
  .replaceAll(legacyMarker, "")
  .replaceAll(oldestMarker, "")
  .replace(/\n\t+#subscriptions =/, "\n\t#subscriptions =")
  .replace(
    "\t#logger;\n\t#decodeFailureHook;\n\t#claimDeletedHook;\n\t#tombstoneDrainPromise;\n",
    "\t#logger;\n",
  )
  .replace(
    "\t\tthis.#logger = options.logger;\n\t\tthis.#decodeFailureHook = options.onDecodeFailure;\n\t\tthis.#claimDeletedHook = options.onClaimDeleted;\n",
    "\t\tthis.#logger = options.logger;\n",
  )
  // v2-v5 each inserted some portion of these helpers. Replace the whole
  // owned region, rather than trying to infer which individual migration ran.
  .replace(
    /\n\t#tombstoneKey\(\) \{[\s\S]*?\n\tasync publish\(/,
    "\n\tasync publish(",
  )
  .replace(
    "\t\tconst xaddOptions = {}; // PEL-safe: never MAXLEN-trim live streams.",
    `\t\tconst xaddOptions = {};
\t\tif (this.#maxStreamLength > 0) xaddOptions.TRIM = {
\t\t\tstrategy: "MAXLEN",
\t\t\tstrategyModifier: "~",
\t\t\tthreshold: this.#maxStreamLength
\t\t};`,
  )
  .replace(
    `\t\t\t\tconst claim = await this.#writeClient.xAutoClaim(sub.streamKey, sub.group, sub.consumer, this.#reclaimIdleMs, "0-0", { COUNT: 100 });
\t\t\t\tconst messages = claim?.messages ?? [];
\t\t\t\tfor (const streamId of claim?.deletedMessages ?? []) {
\t\t\t\t\tif (!this.#claimDeletedHook) {
\t\t\t\t\t\tthis.#logger?.warn?.("redis-streams: XAUTOCLAIM found deleted PEL entry without audit hook", { topic: sub.topic, streamId });
\t\t\t\t\t\tcontinue;
\t\t\t\t\t}
\t\t\t\t\ttry {
\t\t\t\t\t\tawait this.#claimDeletedHook({ topic: sub.topic, streamId, group: sub.group, consumer: sub.consumer, errorCode: "STREAM_ENTRY_TRIMMED" });
\t\t\t\t\t} catch (hookErr) {
\t\t\t\t\t\tthis.#logger?.warn?.("redis-streams: deleted PEL audit failed", { topic: sub.topic, streamId, err: errorText(hookErr) });
\t\t\t\t\t}
\t\t\t\t}`,
    `\t\t\t\tconst messages = (await this.#writeClient.xAutoClaim(sub.streamKey, sub.group, sub.consumer, this.#reclaimIdleMs, "0-0", { COUNT: 100 }))?.messages ?? [];`,
  );

// Canonicalise the remaining v6-owned call sites too. Older releases may have
// only a subset of these changes; all are restored to the upstream shape before
// the clean transform below is applied.
source = source
  .replace(
    "\t\tconst xaddOptions = {}; // Retention runs after write with PEL awareness.",
    `\t\tconst xaddOptions = {};
\t\tif (this.#maxStreamLength > 0) xaddOptions.TRIM = {
\t\t\tstrategy: "MAXLEN",
\t\t\tstrategyModifier: "~",
\t\t\tthreshold: this.#maxStreamLength
\t\t};`,
  )
  .replace(
    /\t\tconst publishWithRetention = promise\.then\(async \(\) => \{\n\t\t\tawait this\.#maintainStreamRetention\(streamKey\);\n\t\t\}\);\n\t\tthis\.#pendingPublishes\.add\(publishWithRetention\);\n\t\ttry \{\n\t\t\tawait publishWithRetention;\n\t\t\} finally \{\n\t\t\tthis\.#pendingPublishes\.delete\(publishWithRetention\);\n\t\t\}/,
    "\t\tthis.#pendingPublishes.add(promise);\n\t\ttry {\n\t\t\tawait promise;\n\t\t} finally {\n\t\t\tthis.#pendingPublishes.delete(promise);\n\t\t}",
  )
  .replace(
    "\t\t\t\tawait this.#drainTombstones();\n\t\t\t\tconst messages = await this.#claimAndQueueTombstones(sub);",
    '\t\t\t\tconst messages = (await this.#writeClient.xAutoClaim(sub.streamKey, sub.group, sub.consumer, this.#reclaimIdleMs, "0-0", { COUNT: 100 }))?.messages ?? [];',
  )
  .replaceAll(
    /\t\t\t\ttry \{\n\t\t\t\t\tawait this\.#deliverMessage\(sub, entry\.id, entry\.message\);\n\t\t\t\t\} catch \(deliveryErr\) \{[\s\S]*?\n\t\t\t\t\}/g,
    "\t\t\t\tawait this.#deliverMessage(sub, entry.id, entry.message);",
  )
  .replace(
    /\t\t\} catch \(err\) \{\n\t\t\tconst rawBytes = new Uint8Array\(Buffer\.from\(fields\.event \?\? "", "utf8"\)\);[\s\S]*?\n\t\t\treturn;\n\t\t\}/,
    `\t\t} catch (err) {
\t\t\tthis.#logger?.debug?.("redis-streams: malformed payload, dropping", {
\t\t\t\ttopic: sub.topic,
\t\t\t\tstreamId,
\t\t\t\terr: err instanceof Error ? err.message : err
\t\t\t});
\t\t\treturn;
\t\t}`,
  )
  // The read-loop body is an owned safety boundary. Replace it as one unit so
  // a partial/failed prior migration cannot leave nested or missing catches.
  .replace(
    /(\t\t\tif \(!result \|\| result\.length === 0\) continue;\n\t\t\tfor \(const stream of result\) for \(const entry of stream\.messages\) \{\n\t\t\t\tif \(sub\.stopped\) return;\n\t\t\t\tsub\.lastId = entry\.id;)[\s\S]*?(\n\t\t\t\}\n\t\t\}\n\t\}\n\tasync #deliverMessage)/,
    "$1\n\t\t\t\tawait this.#deliverMessage(sub, entry.id, entry.message);$2",
  );

let patched = source
  .replace(
    "\t#logger;\n",
    `\t#logger;
\t#decodeFailureHook;
\t#claimDeletedHook;
\t#tombstoneDrainPromise;
\t// ${marker}
`,
  )
  .replace(
    "\t\tthis.#logger = options.logger;\n",
    `\t\tthis.#logger = options.logger;
\t\tthis.#decodeFailureHook = options.onDecodeFailure;
\t\tthis.#claimDeletedHook = options.onClaimDeleted;
`,
  )
  .replace(
    "\t#streamKey(topic) {\n\t\treturn `${this.#keyPrefix}:${topic}`;\n\t}",
    `\t#streamKey(topic) {
\t\treturn \`${"${this.#keyPrefix}"}:\${topic}\`;
\t}
\t#tombstoneKey() {
\t\treturn \`${"${this.#keyPrefix}"}:__phase8-tombstones\`;
\t}
${streamIdHelpers}
${retentionMethod}
\tasync #drainTombstones() {
\t\tif (!this.#claimDeletedHook) return;
\t\tif (this.#tombstoneDrainPromise) return this.#tombstoneDrainPromise;
\t\tconst task = (async () => {
\t\t\tconst key = this.#tombstoneKey();
\t\t\tconst entries = await this.#writeClient.xRange(key, "-", "+", { COUNT: 100 });
\t\t\tfor (const entry of entries) {
\t\t\t\tconst item = entry.message;
\t\t\t\tif (![item?.topic, item?.streamId, item?.group, item?.consumer].every((value) => typeof value === "string")) continue;
${retainTombstoneHookFailure}
\t\t\t}
\t\t})();
\t\tthis.#tombstoneDrainPromise = task;
\t\ttry { await task; } finally { this.#tombstoneDrainPromise = undefined; }
\t}
\tasync #enqueueTombstone(input) {
\t\tawait this.#writeClient.xAdd(this.#tombstoneKey(), "*", input);
\t\tawait this.#drainTombstones();
\t}
\tasync #claimAndQueueTombstones(sub) {
\t\tconst script = "local r=redis.call('XAUTOCLAIM',KEYS[1],ARGV[1],ARGV[2],ARGV[3],'0-0','COUNT',100); for _,id in ipairs(r[3] or {}) do redis.call('XADD',KEYS[2],'*','topic',ARGV[4],'streamId',id,'group',ARGV[1],'consumer',ARGV[2],'errorCode','STREAM_ENTRY_TRIMMED') end; return r";
\t\tconst claimed = await this.#writeClient.sendCommand(["EVAL", script, "2", sub.streamKey, this.#tombstoneKey(), sub.group, sub.consumer, String(this.#reclaimIdleMs), sub.topic]);
\t\tconst rawMessages = Array.isArray(claimed) && Array.isArray(claimed[1]) ? claimed[1] : [];
\t\treturn rawMessages.map((entry) => ({
\t\t\tid: entry[0],
\t\t\tmessage: Object.fromEntries(Array.isArray(entry[1]) ? entry[1].reduce((pairs, value, index) => index % 2 === 0 ? [...pairs, [value, entry[1][index + 1]]] : pairs, []) : []),
\t\t}));
\t}`,
  )
  .replace(
    `\t\tconst xaddOptions = {};
\t\tif (this.#maxStreamLength > 0) xaddOptions.TRIM = {
\t\t\tstrategy: "MAXLEN",
\t\t\tstrategyModifier: "~",
\t\t\tthreshold: this.#maxStreamLength
\t\t};`,
    "\t\tconst xaddOptions = {}; // Retention runs after write with PEL awareness.",
  )
  .replace(
    "\t\tthis.#pendingPublishes.add(promise);",
    `\t\tconst publishWithRetention = promise.then(async () => {
\t\t\tawait this.#maintainStreamRetention(streamKey);
\t\t});
\t\tthis.#pendingPublishes.add(publishWithRetention);`,
  )
  .replace("\t\t\tawait promise;", "\t\t\tawait publishWithRetention;")
  .replace(
    "\t\t\tthis.#pendingPublishes.delete(promise);",
    "\t\t\tthis.#pendingPublishes.delete(publishWithRetention);",
  )
  .replace(
    `\t\t\t\tconst messages = (await this.#writeClient.xAutoClaim(sub.streamKey, sub.group, sub.consumer, this.#reclaimIdleMs, "0-0", { COUNT: 100 }))?.messages ?? [];`,
    `\t\t\t\tawait this.#drainTombstones();
\t\t\t\tconst messages = await this.#claimAndQueueTombstones(sub);`,
  )
  .replace(
    /\t\t\tthis\.#logger\?\.debug\?\.\("redis-streams: malformed payload, dropping", \{[\s\S]*?\n\t\t\treturn;\n\t\t\}/,
    `\t\t\tconst rawBytes = new Uint8Array(Buffer.from(fields.event ?? "", "utf8"));
\t\t\tif (!this.#decodeFailureHook) {
\t\t\t\tthis.#logger?.warn?.("redis-streams: malformed payload retained without decode hook", { topic: sub.topic, streamId });
\t\t\t\treturn;
\t\t\t}
\t\t\ttry {
\t\t\t\tawait this.#decodeFailureHook({ topic: sub.topic, streamId, group: sub.group, consumer: sub.consumer, pel: { pending: true }, rawBytes, errorCode: "EVENT_INVALID" });
\t\t\t\tawait this.#writeClient.xAck(sub.streamKey, sub.group, streamId);
\t\t\t} catch (hookErr) {
\t\t\t\t// Leave only this entry in the PEL. A hook outage must not reject
\t\t\t\t// #deliverMessage and kill the subscription's XREADGROUP loop.
\t\t\t\tthis.#logger?.warn?.("redis-streams: decode audit retry pending", { topic: sub.topic, streamId, err: errorText(hookErr) });
\t\t\t}
\t\t\treturn;
\t\t}`,
  )
  .replace(
    '\t\t\tconst result = sub.cb(event, ack, nack);\n\t\t\tif (result && typeof result.catch === "function") result.catch(async () => {\n\t\t\t\tawait nack();\n\t\t\t});',
    "\t\t\tawait sub.cb(event, ack, nack);",
  )
  .replace(
    /\t\ttry \{\n\t\t\tawait sub\.cb\(event, ack, nack\);\n\t\t\} catch(?: \(err\))? \{[\s\S]*?\n\t\t\}/,
    retainDeliveryCatch,
  )
  .replaceAll(
    "\t\t\t\tawait this.#deliverMessage(sub, entry.id, entry.message);",
    `\t\t\t\ttry {
\t\t\t\t\tawait this.#deliverMessage(sub, entry.id, entry.message);
\t\t\t\t} catch (deliveryErr) {
\t\t\t\t\t// Retain the failed entry and keep consuming unread records.
\t\t\t\t\tthis.#logger?.warn?.("redis-streams: delivery retry pending", { topic: sub.topic, streamId: entry.id, err: errorText(deliveryErr) });
\t\t\t\t\tawait new Promise((resolve) => setTimeout(resolve, 100));
\t\t\t\t}`,
  );

requireReplacement(patched !== source, "runtime transform");

// These are semantic patch boundaries, not a shallow marker check. Keep the
// diagnostics explicit: an upstream layout change must fail postinstall before
// it can advertise a version that did not install every safety property.
const runtimeInvariants = [
  ["version marker", `// ${marker}`],
  ["decode hook field", "#decodeFailureHook;"],
  ["tombstone drain field", "#tombstoneDrainPromise;"],
  ["decode hook wiring", "this.#decodeFailureHook = options.onDecodeFailure;"],
  ["BigInt stream IDs", 'left.split("-").map(BigInt)'],
  ["PEL-aware MINID", 'XTRIM", streamKey, "MINID'],
  ["caught-up MAXLEN", 'XTRIM", streamKey, "MAXLEN'],
  ["atomic tombstone claim", '"EVAL", script, "2"'],
  ["tombstone retry", "tombstone audit retry pending"],
  ["post-publish retention", "const publishWithRetention = promise.then"],
  ["tombstone draining", "await this.#drainTombstones();"],
  ["decode retain without loop rejection", "decode audit retry pending"],
  ["awaited delivery", "await sub.cb(event, ack, nack);"],
  ["typed delivery retain", "PHASE8_RETAIN_DELIVERY"],
  ["read-loop delivery backoff", "delivery retry pending"],
];
for (const [label, snippet] of runtimeInvariants) {
  requireReplacement(
    patched.includes(snippet),
    `runtime invariant missing: ${label}`,
  );
}
requireReplacement(
  /await this\.#decodeFailureHook\([^\n]+\);\n\t\t\t\tawait this\.#writeClient\.xAck[\s\S]*?catch \(hookErr\)[\s\S]*?decode audit retry pending/.test(
    patched,
  ),
  "runtime invariant missing: decode hook catch/retain",
);
requireReplacement(
  /async #runReadLoop\(sub\) \{[\s\S]*?try \{[\s\S]*?await this\.#deliverMessage\(sub, entry\.id, entry\.message\);[\s\S]*?delivery retry pending/.test(
    patched,
  ),
  "runtime invariant missing: read-loop delivery catch/backoff",
);

const patchedTypes = canonicalTypeDeclarations(types);
requireReplacement(
  patchedTypes.includes(typeDeclarations),
  "type declarations",
);

if (patched !== runtime) await writeAtomically(runtimePath, patched);
if (patchedTypes !== types) await writeAtomically(typesPath, patchedTypes);
