import { readFile } from "node:fs/promises";

import { afterEach, describe, expect, it } from "vitest";

import { migrateOperationalStore } from "../../src/db/migrate.js";
import {
  persistRedisClaimDeleted,
  persistRedisDecodeFailure,
} from "../../src/db/redis-decode-failure-operations.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];
afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

type Pending = {
  id: string;
  bytes: Uint8Array;
  consumer: string;
  deliveries: number;
  acked: boolean;
  deleted?: boolean;
};

/**
 * Hermetic Redis Streams protocol model for the vendored decode boundary. It
 * models PEL ownership/delivery count, XAUTOCLAIM, MAXLEN approximation and
 * restart without opening a Redis connection.
 */
class FakeRedisStreamsTransport {
  readonly pending: Pending[] = [];
  readonly operations: string[] = [];
  constructor(readonly maxLength = 100_000) {}

  add(id: string, text: string) {
    this.pending.push({
      id,
      bytes: new TextEncoder().encode(text),
      consumer: "consumer-a",
      deliveries: 1,
      acked: false,
    });
    // The vendored patch deliberately does not issue MAXLEN while a stream can
    // have a PEL. This harness makes that invariant observable on restart.
  }

  async decodeAndDeliver(
    item: Pending,
    hook: (input: {
      streamId: string;
      topic: string;
      group: string;
      consumer: string;
      rawBytes: Uint8Array;
    }) => Promise<void>,
  ) {
    try {
      JSON.parse(new TextDecoder().decode(item.bytes));
    } catch {
      this.operations.push("decode");
      await hook({
        streamId: item.id,
        topic: "security.alert.received",
        group: "security-workflow-starters",
        consumer: item.consumer,
        rawBytes: item.bytes,
      });
      this.operations.push("dlq-committed");
      item.acked = true;
      this.operations.push("xack");
    }
  }

  /**
   * Mirrors the patched adapter's awaited callback/catch/nack branch. A typed
   * retain result exits before nack, so deliveryAttempt stays at 1 even when
   * Redis has reclaimed the same PEL entry many times.
   */
  async deliverCallback(
    item: Pending,
    callback: () => Promise<void>,
    maxDeliveryAttempts = 5,
  ) {
    try {
      await callback();
      item.acked = true;
      this.operations.push("xack");
    } catch (error) {
      if (
        error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "PHASE8_RETAIN_DELIVERY"
      ) {
        this.operations.push("retain-pel");
        return;
      }
      const deliveryAttempt = 1;
      if (deliveryAttempt >= maxDeliveryAttempts) {
        item.acked = true;
        this.operations.push("terminal-xack");
        return;
      }
      this.operations.push("nack-republish");
      item.acked = true;
      this.operations.push("xack-original");
    }
  }

  xautoclaim(id: string, consumer: string) {
    const item = this.pending.find((candidate) => candidate.id === id);
    if (!item || item.acked) return { messages: [], deletedMessages: [] };
    if (item.deleted) {
      this.operations.push("xautoclaim-deleted");
      return { messages: [], deletedMessages: [id] };
    }
    item.consumer = consumer;
    item.deliveries += 1;
    this.operations.push("xautoclaim");
    return { messages: [item], deletedMessages: [] };
  }

  simulateUnsafeTrim(id: string) {
    const item = this.pending.find((candidate) => candidate.id === id);
    if (item) item.deleted = true;
  }
}

/** Minimal protocol model for the durable Redis tombstone stream in the patch. */
class TombstoneQueue {
  readonly entries: Array<{
    id: string;
    topic: string;
    streamId: string;
    group: string;
    consumer: string;
  }> = [];

  enqueue(streamId: string) {
    this.entries.push({
      id: `tombstone-${streamId}`,
      topic: "security.alert.received",
      streamId,
      group: "security-workflow-starters",
      consumer: "consumer-restarted",
    });
  }

  async drain(hook: (entry: (typeof this.entries)[number]) => Promise<void>) {
    for (const entry of [...this.entries]) {
      await hook(entry);
      this.entries.splice(this.entries.indexOf(entry), 1);
    }
  }
}

/** Mirrors the patch's two retention modes without opening a Redis socket. */
class PelSafeRetentionModel {
  readonly entries: string[] = [];
  readonly operations: string[] = [];
  groups: Array<{
    name: string;
    lag?: number | null;
    lastDelivered?: string;
    pending?: string[];
  }> = [];

  private before(left: string, right: string) {
    const [leftMs = 0n, leftSequence = 0n] = left.split("-").map(BigInt);
    const [rightMs = 0n, rightSequence = 0n] = right.split("-").map(BigInt);
    return (
      leftMs < rightMs || (leftMs === rightMs && leftSequence < rightSequence)
    );
  }

  private isStreamId(value: unknown): value is string {
    return typeof value === "string" && /^\d+-\d+$/u.test(value);
  }

  private decision(maxLength: number) {
    let safeCutoff: string | undefined;
    let allGroupsCaughtUp = true;
    const addCutoff = (streamId: string) => {
      if (!safeCutoff || this.before(streamId, safeCutoff))
        safeCutoff = streamId;
    };
    for (const group of this.groups) {
      const lag = group.lag;
      if (
        !Number.isSafeInteger(lag) ||
        lag === undefined ||
        lag === null ||
        lag < 0 ||
        !this.isStreamId(group.lastDelivered) ||
        group.lastDelivered === "0-0" ||
        !Array.isArray(group.pending)
      )
        return "NO_TRIM";
      if (group.pending.length > 0) {
        const earliestPending = group.pending.reduce((earliest, pending) =>
          this.before(pending, earliest) ? pending : earliest,
        );
        allGroupsCaughtUp = false;
        addCutoff(earliestPending);
      }
      if (lag > 0) {
        allGroupsCaughtUp = false;
        addCutoff(group.lastDelivered);
      }
    }
    if (safeCutoff) return `MINID:${safeCutoff}`;
    return allGroupsCaughtUp ? `MAXLEN:${maxLength}` : "NO_TRIM";
  }

  publish(id: string, maxLength: number) {
    this.entries.push(id);
    const decision = this.decision(maxLength);
    this.operations.push(decision);
    if (decision.startsWith("MINID:")) {
      const cutoff = decision.slice("MINID:".length);
      this.entries.splice(
        0,
        this.entries.findIndex((entry) => entry === cutoff),
      );
      return;
    }
    if (decision === "NO_TRIM") {
      return;
    }
    while (this.entries.length > maxLength) this.entries.shift();
  }
}

describe("vendored Redis Streams 0.4.0 decode hook", () => {
  it("persists only hash/size/safe PEL metadata before ACKing raw poison", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const stream = new FakeRedisStreamsTransport();
    stream.add("171-0", '{"truncated"');
    await stream.decodeAndDeliver(stream.pending[0]!, async (failure) => {
      await persistRedisDecodeFailure(store, {
        ...failure,
        errorCode: "EVENT_INVALID",
      });
    });
    expect(stream.operations).toEqual(["decode", "dlq-committed", "xack"]);
    expect(stream.pending[0]?.acked).toBe(true);
    const stored = await store.execute({
      sql: "SELECT * FROM redis_decode_failures",
    });
    expect(stored.rows[0]).toMatchObject({
      stream_id: "171-0",
      consumer_group: "security-workflow-starters",
      payload_size: 12,
      error_code: "EVENT_INVALID",
    });
    expect(JSON.stringify(stored.rows[0])).not.toContain("truncated");
    await expect(
      store.execute({ sql: "SELECT count(*) AS n FROM dead_letter_events" }),
    ).resolves.toMatchObject({ rows: [{ n: 1 }] });
    await expect(
      store.execute({
        sql: "SELECT type, payload_json FROM outbox_events WHERE type = 'security.dead-letter'",
      }),
    ).resolves.toMatchObject({
      rows: [
        {
          type: "security.dead-letter",
          payload_json: expect.not.stringContaining("truncated"),
        },
      ],
    });
    store.close();
  });

  it("retains PEL on DLQ failure, then permits XAUTOCLAIM after a restart", async () => {
    const stream = new FakeRedisStreamsTransport(1);
    stream.add("172-0", "not-json");
    await expect(
      stream.decodeAndDeliver(stream.pending[0]!, async () => {
        throw new Error("storage unavailable");
      }),
    ).rejects.toThrow("storage unavailable");
    expect(stream.pending[0]?.acked).toBe(false);
    const reclaimed = stream.xautoclaim("172-0", "consumer-b");
    expect(reclaimed.messages[0]).toMatchObject({
      consumer: "consumer-b",
      deliveries: 2,
    });
    expect(stream.operations).toEqual(["decode", "xautoclaim"]);
  });

  it("keeps a failed callback in the PEL through five reclaim attempts and ACKs exactly once after durable recovery", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const stream = new FakeRedisStreamsTransport();
    stream.add("172-5", "schema-valid-but-untrusted");
    let storageAvailable = false;
    let callbackCalls = 0;
    const callback = async () => {
      callbackCalls += 1;
      if (!storageAvailable) {
        const error = Object.assign(new Error("durability unavailable"), {
          code: "PHASE8_RETAIN_DELIVERY",
        });
        throw error;
      }
      await persistRedisDecodeFailure(store, {
        streamId: "172-5",
        topic: "security.alert.received",
        group: "security-workflow-starters",
        consumer: "consumer-recovered",
        rawBytes: stream.pending[0]!.bytes,
        errorCode: "EVENT_INVALID",
      });
    };
    for (let delivery = 1; delivery <= 5; delivery += 1) {
      const item =
        delivery === 1
          ? stream.pending[0]!
          : stream.xautoclaim("172-5", `consumer-${delivery}`).messages[0]!;
      await stream.deliverCallback(item, callback, 5);
    }
    expect(stream.pending[0]).toMatchObject({ acked: false, deliveries: 5 });
    expect(stream.operations).not.toContain("nack-republish");
    expect(stream.operations).not.toContain("terminal-xack");
    expect(
      stream.operations.filter((item) => item === "retain-pel"),
    ).toHaveLength(5);
    expect(
      await store.execute({
        sql: "SELECT count(*) AS n FROM dead_letter_events",
      }),
    ).toMatchObject({ rows: [{ n: 0 }] });

    storageAvailable = true;
    const reclaimed = stream.xautoclaim("172-5", "consumer-recovered");
    await stream.deliverCallback(reclaimed.messages[0]!, callback, 5);
    expect(stream.pending[0]).toMatchObject({ acked: true, deliveries: 6 });
    expect(stream.operations.filter((item) => item === "xack")).toHaveLength(1);
    expect(callbackCalls).toBe(6);
    await expect(
      store.execute({
        sql: `SELECT
          (SELECT count(*) FROM redis_decode_failures) AS failures,
          (SELECT count(*) FROM dead_letter_events) AS dead_letters,
          (SELECT count(*) FROM outbox_events WHERE type = 'security.dead-letter') AS outbox`,
      }),
    ).resolves.toMatchObject({
      rows: [{ failures: 1, dead_letters: 1, outbox: 1 }],
    });
    const adapter = await readFile(
      new URL(
        "../../node_modules/@mastra/redis-streams/dist/index.js",
        import.meta.url,
      ),
      "utf8",
    );
    expect(adapter).toContain("phase8-redis-retention-tombstone-v6");
    expect(adapter).toMatch(
      /PHASE8_RETAIN_DELIVERY[\s\S]*?return;[\s\S]*?await nack\(\)/,
    );
    store.close();
  });

  it("retries a queued XAUTOCLAIM tombstone after local persistence failure and restart", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const stream = new FakeRedisStreamsTransport(1);
    stream.add("173-0", "not-json");
    // This simulates an old unsafe MAXLEN deployment; the patched publisher
    // keeps the PEL entry instead, while claimers still audit legacy tombstones.
    stream.simulateUnsafeTrim("173-0");
    const claim = stream.xautoclaim("173-0", "consumer-restarted");
    expect(claim).toEqual({ messages: [], deletedMessages: ["173-0"] });
    const queue = new TombstoneQueue();
    queue.enqueue("173-0");
    await expect(
      queue.drain(async () => {
        throw new Error("local persistence unavailable");
      }),
    ).rejects.toThrow("local persistence unavailable");
    expect(queue.entries).toHaveLength(1);
    // A restarted consumer drains the same Redis queue. The entry is removed
    // only after its idempotent local transaction commits.
    await queue.drain(async (entry) => {
      await persistRedisClaimDeleted(store, {
        topic: entry.topic,
        streamId: entry.streamId,
        group: entry.group,
        consumer: entry.consumer,
        errorCode: "STREAM_ENTRY_TRIMMED",
      });
    });
    expect(queue.entries).toHaveLength(0);
    const result = await store.execute({
      sql: `SELECT d.error_code, o.payload_json
        FROM dead_letter_events d JOIN outbox_events o
          ON o.type = 'security.dead-letter'`,
    });
    expect(result.rows).toEqual([
      expect.objectContaining({
        error_code: "STREAM_ENTRY_TRIMMED",
        payload_json: expect.stringContaining('"payloadAvailable":false'),
      }),
    ]);
    store.close();
  });

  it("uses the minimum safe frontier across every group's PEL and unread lag", () => {
    const pelAUnreadB = new PelSafeRetentionModel();
    pelAUnreadB.entries.push("1-0", "10-0", "149-0", "150-0");
    pelAUnreadB.groups = [
      { name: "a", lag: 0, lastDelivered: "200-0", pending: ["150-0"] },
      { name: "b", lag: 149, lastDelivered: "10-0", pending: [] },
    ];
    pelAUnreadB.publish("201-0", 2);
    expect(pelAUnreadB.operations).toEqual(["MINID:10-0"]);
    expect(pelAUnreadB.entries).toEqual(["10-0", "149-0", "150-0", "201-0"]);

    const unreadAPelB = new PelSafeRetentionModel();
    unreadAPelB.entries.push("1-0", "11-0", "149-0", "150-0");
    unreadAPelB.groups = [
      { name: "a", lag: 139, lastDelivered: "11-0", pending: [] },
      { name: "b", lag: 0, lastDelivered: "200-0", pending: ["150-0"] },
    ];
    unreadAPelB.publish("201-0", 2);
    expect(unreadAPelB.operations).toEqual(["MINID:11-0"]);
    expect(unreadAPelB.entries).toEqual(["11-0", "149-0", "150-0", "201-0"]);

    const multiplePending = new PelSafeRetentionModel();
    multiplePending.entries.push("1-0", "20-0", "40-0", "80-0");
    multiplePending.groups = [
      { name: "a", lag: 0, lastDelivered: "100-0", pending: ["80-0", "40-0"] },
      { name: "b", lag: 0, lastDelivered: "100-0", pending: ["20-0"] },
    ];
    multiplePending.publish("101-0", 2);
    expect(multiplePending.operations).toEqual(["MINID:20-0"]);
    expect(multiplePending.entries).toEqual(["20-0", "40-0", "80-0", "101-0"]);
  });

  it("does not trim without a safe group frontier, and bounds only proven-safe streams", () => {
    const neverDelivered = new PelSafeRetentionModel();
    neverDelivered.entries.push("1-0", "149-0", "150-0");
    neverDelivered.groups = [
      { name: "a", lag: 0, lastDelivered: "200-0", pending: ["150-0"] },
      { name: "b", lag: 149, lastDelivered: "0-0", pending: [] },
    ];
    neverDelivered.publish("201-0", 2);
    expect(neverDelivered.operations).toEqual(["NO_TRIM"]);
    expect(neverDelivered.entries).toEqual(["1-0", "149-0", "150-0", "201-0"]);

    const unknownLag = new PelSafeRetentionModel();
    unknownLag.entries.push("1-0", "2-0", "3-0");
    unknownLag.groups = [
      { name: "unknown", lag: null, lastDelivered: "2-0", pending: [] },
    ];
    unknownLag.publish("4-0", 2);
    expect(unknownLag.operations).toEqual(["NO_TRIM"]);

    const caughtUpGroups = new PelSafeRetentionModel();
    caughtUpGroups.groups = [
      { name: "a", lag: 0, lastDelivered: "3-0", pending: [] },
      { name: "b", lag: 0, lastDelivered: "3-0", pending: [] },
    ];
    caughtUpGroups.publish("1-0", 2);
    caughtUpGroups.publish("2-0", 2);
    caughtUpGroups.publish("3-0", 2);
    expect(caughtUpGroups.entries).toEqual(["2-0", "3-0"]);
    expect(caughtUpGroups.operations).toEqual([
      "MAXLEN:2",
      "MAXLEN:2",
      "MAXLEN:2",
    ]);

    const noGroups = new PelSafeRetentionModel();
    noGroups.publish("1-0", 1);
    noGroups.publish("2-0", 1);
    expect(noGroups.entries).toEqual(["2-0"]);
    expect(noGroups.operations).toEqual(["MAXLEN:1", "MAXLEN:1"]);
  });
});
