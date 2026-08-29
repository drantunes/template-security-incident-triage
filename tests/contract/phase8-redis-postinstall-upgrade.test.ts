import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFile = promisify(execFileCallback);
const projectRoot = fileURLToPath(new URL("../..", import.meta.url));
const patchScript = join(
  projectRoot,
  "scripts/apply-vendored-redis-streams-patch.mjs",
);
const vendorDirectory = join(
  "node_modules",
  "@mastra",
  "redis-streams",
  "dist",
);
const runtimeRelativePath = join(vendorDirectory, "index.js");
const typesRelativePath = join(vendorDirectory, "index.d.ts");
const marker = "phase8-redis-retention-tombstone-v6";

let fixtureRoot = "";
let baseRuntime = "";
let baseTypes = "";
let cleanRuntime = "";
let cleanTypes = "";

const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");

async function writeFixture(name: string, runtime: string, types: string) {
  const root = join(fixtureRoot, name);
  await mkdir(dirname(join(root, runtimeRelativePath)), { recursive: true });
  await writeFile(join(root, runtimeRelativePath), runtime, "utf8");
  await writeFile(join(root, typesRelativePath), types, "utf8");
  return root;
}

async function readFixture(root: string) {
  return {
    runtime: await readFile(join(root, runtimeRelativePath), "utf8"),
    types: await readFile(join(root, typesRelativePath), "utf8"),
  };
}

async function runPostinstall(root: string) {
  return execFile(process.execPath, [patchScript], {
    env: { ...process.env, PHASE8_REDIS_STREAMS_PATCH_ROOT: root },
  });
}

function legacyRuntime(version: 2 | 3 | 4 | 5) {
  const previousMarker = `phase8-redis-retention-tombstone-v${version}`;
  let legacy = cleanRuntime.replace(marker, previousMarker);
  // This is the historical v5 failure mode: the hook rejection reaches the
  // read loop because the await has no local catch. Earlier fixtures retain
  // the same partial shape to verify full convergence rather than marker swap.
  legacy = legacy.replace(
    /\t\t\ttry \{\n\t\t\t\tawait this\.#decodeFailureHook\([^\n]+\);\n\t\t\t\tawait this\.#writeClient\.xAck\(sub\.streamKey, sub\.group, streamId\);\n\t\t\t\} catch \(hookErr\) \{[\s\S]*?\n\t\t\t\}\n\t\t\treturn;/,
    '\t\t\tawait this.#decodeFailureHook({ topic: sub.topic, streamId, group: sub.group, consumer: sub.consumer, pel: { pending: true }, rawBytes, errorCode: "EVENT_INVALID" });\n\t\t\tawait this.#writeClient.xAck(sub.streamKey, sub.group, streamId);\n\t\t\treturn;',
  );
  if (version === 2) {
    legacy = legacy.replaceAll(".map(BigInt)", ".map(Number)");
  }
  if (version === 3) {
    legacy = legacy.replace(
      "tombstone audit retry pending",
      "deleted PEL audit failed",
    );
  }
  if (version === 4) {
    legacy = legacy.replace("delivery retry pending", "delivery failed");
  }
  return legacy;
}

function partialTypes() {
  return baseTypes.replace(
    "    logger?: {\n",
    "    onDecodeFailure?: () => Promise<void>;\n    logger?: {\n",
  );
}

beforeAll(async () => {
  fixtureRoot = await mkdtemp(join(tmpdir(), "phase8-redis-postinstall-"));
  // npm ci --ignore-scripts gives us the actual package 0.4.0, not a reverse
  // engineered fixture, while remaining hermetic/offline.
  await cp(
    join(projectRoot, "package.json"),
    join(fixtureRoot, "package.json"),
  );
  await cp(
    join(projectRoot, "package-lock.json"),
    join(fixtureRoot, "package-lock.json"),
  );
  await execFile("npm", ["ci", "--offline", "--ignore-scripts"], {
    cwd: fixtureRoot,
  });
  baseRuntime = await readFile(join(fixtureRoot, runtimeRelativePath), "utf8");
  baseTypes = await readFile(join(fixtureRoot, typesRelativePath), "utf8");

  const cleanRoot = join(fixtureRoot, "clean");
  await mkdir(cleanRoot);
  await mkdir(join(cleanRoot, vendorDirectory), { recursive: true });
  await writeFile(join(cleanRoot, runtimeRelativePath), baseRuntime, "utf8");
  await writeFile(join(cleanRoot, typesRelativePath), baseTypes, "utf8");
  await runPostinstall(cleanRoot);
  ({ runtime: cleanRuntime, types: cleanTypes } = await readFixture(cleanRoot));
  // The fixture deliberately performs an offline npm install of the real
  // package.  Hosted runners can take longer than Vitest's 10 s default even
  // when the install succeeds, so this setup has an explicit bounded budget.
}, 60_000);

afterAll(async () => {
  if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

describe("vendored Redis Streams postinstall v6 convergence", () => {
  it.each([
    ["base", () => baseRuntime, () => baseTypes],
    ["v2 runtime / v6 types", () => legacyRuntime(2), () => cleanTypes],
    ["v3 runtime / base types", () => legacyRuntime(3), () => baseTypes],
    ["v4 runtime / partial types", () => legacyRuntime(4), partialTypes],
    ["v5 runtime / v6 types", () => legacyRuntime(5), () => cleanTypes],
    ["v6 runtime / base types", () => cleanRuntime, () => baseTypes],
  ])(
    "converges %s to the clean v6 runtime and declarations",
    async (_name, runtimeForFixture, typesForFixture) => {
      const caseRoot = join(
        fixtureRoot,
        `case-${_name.replaceAll(/[^a-z0-9]+/gi, "-")}`,
      );
      await mkdir(caseRoot);
      await mkdir(join(caseRoot, vendorDirectory), { recursive: true });
      await writeFile(
        join(caseRoot, runtimeRelativePath),
        runtimeForFixture(),
        "utf8",
      );
      await writeFile(
        join(caseRoot, typesRelativePath),
        typesForFixture(),
        "utf8",
      );
      await runPostinstall(caseRoot);
      const first = await readFixture(caseRoot);
      expect(first.runtime).toBe(cleanRuntime);
      expect(first.types).toBe(cleanTypes);
      expect(digest(first.runtime)).toBe(digest(cleanRuntime));
      expect(digest(first.types)).toBe(digest(cleanTypes));

      await runPostinstall(caseRoot);
      expect(await readFixture(caseRoot)).toEqual(first);
    },
  );

  it("fails diagnostically rather than trusting an unverifiable v5 marker", async () => {
    const name = "unknown-v5";
    const root = join(fixtureRoot, name);
    await mkdir(root);
    await writeFixture(
      name,
      `// phase8-redis-retention-tombstone-v5\n`,
      baseTypes,
    );
    await expect(runPostinstall(root)).rejects.toThrow("runtime transform");
  });

  it("keeps the actual v5-upgraded read loop alive when the decode hook rejects", async () => {
    const warnings: string[] = [];
    const acknowledged: string[] = [];
    let unblockRead: (() => void) | undefined;
    const blockedRead = new Promise<void>((resolve) => {
      unblockRead = resolve;
    });
    let reads = 0;
    const writer = {
      isOpen: false,
      on() {},
      async connect() {
        this.isOpen = true;
      },
      async xGroupCreate() {},
      async xAck(_key: string, _group: string, id: string) {
        acknowledged.push(id);
      },
      async quit() {},
    };
    const reader = {
      on() {},
      async connect() {},
      async quit() {
        unblockRead?.();
      },
      async xReadGroup() {
        reads += 1;
        if (reads === 1)
          return [
            {
              messages: [{ id: "poison", message: { event: "{bad-json" } }],
            },
          ];
        if (reads === 2)
          return [
            {
              messages: [
                {
                  id: "unread-after-poison",
                  message: {
                    event: JSON.stringify({ id: "ok", type: "security.alert" }),
                  },
                },
              ],
            },
          ];
        await blockedRead;
        return [];
      },
    };
    let clientCount = 0;
    (
      globalThis as typeof globalThis & {
        __phase8CreateClient?: () => typeof writer | typeof reader;
      }
    ).__phase8CreateClient = () => (clientCount++ === 0 ? writer : reader);
    try {
      const moduleSource = cleanRuntime
        .replace(
          'import { randomUUID } from "crypto";',
          'const randomUUID = () => "phase8-test";',
        )
        .replace(
          'import { PubSub } from "@mastra/core/events";',
          "class PubSub {}",
        )
        .replace(
          'import { createClient } from "redis";',
          "const createClient = globalThis.__phase8CreateClient;",
        );
      const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleSource).toString("base64")}`;
      const { RedisStreamsPubSub } = await import(moduleUrl);
      let delivered = 0;
      let resolveDelivered: (() => void) | undefined;
      const deliveredPromise = new Promise<void>((resolve) => {
        resolveDelivered = resolve;
      });
      const pubsub = new RedisStreamsPubSub({
        reclaimIntervalMs: 0,
        onDecodeFailure: async () => {
          throw new Error("durability unavailable");
        },
        logger: {
          warn: (message: unknown) => warnings.push(String(message)),
        },
      });
      await pubsub.subscribe(
        "security.alert.received",
        async (_event: unknown, ack: () => Promise<void>) => {
          delivered += 1;
          await ack();
          resolveDelivered?.();
        },
        { group: "security-workflow-starters" },
      );
      await deliveredPromise;
      await pubsub.close();

      expect(delivered).toBe(1);
      expect(acknowledged).toEqual(["unread-after-poison"]);
      expect(warnings).toContain("redis-streams: decode audit retry pending");
    } finally {
      delete (
        globalThis as typeof globalThis & { __phase8CreateClient?: unknown }
      ).__phase8CreateClient;
    }
  });
});
