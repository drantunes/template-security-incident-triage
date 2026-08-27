import { EventEmitterPubSub } from "@mastra/core/events";
import { afterEach, describe, expect, it } from "vitest";

import { OutboxDispatcher } from "../../src/background/outbox-dispatcher.js";
import {
  claimOutboxBatch,
  markOutboxPublished,
  reconcilePublishedAlertsWithoutRun,
} from "../../src/db/outbox-operations.js";
import { createIncidentFromAlert } from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import { fixedClock } from "../../src/domain/clock.js";
import { sequenceIdGenerator } from "../../src/domain/id-generator.js";
import { makeAlert } from "../fixtures/domain.js";
import { makePhase2Config } from "../fixtures/phase2.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];
const silentLogger = { write: () => {} };

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

async function setup() {
  const database = await createTempDatabase();
  databases.push(database);
  const store = database.createStore();
  await migrateOperationalStore(store);
  await createIncidentFromAlert(store, makeAlert(), {
    clock: fixedClock("2026-08-27T12:00:00.000Z"),
    ids: sequenceIdGenerator(["incident-1", "timeline-1", "outbox-1"]),
  });
  return { database, store };
}

describe("outbox dispatcher", () => {
  it("uses an expiring fence and prevents two dispatchers claiming the same row", async () => {
    const { database, store } = await setup();
    const second = database.createStore();
    try {
      const [one, two] = await Promise.all([
        claimOutboxBatch(store, {
          now: "2026-08-27T12:00:00.000Z",
          leaseUntil: "2026-08-27T12:00:10.000Z",
          limit: 1,
        }),
        claimOutboxBatch(second, {
          now: "2026-08-27T12:00:00.000Z",
          leaseUntil: "2026-08-27T12:00:11.000Z",
          limit: 1,
        }),
      ]);
      expect(one.length + two.length).toBe(1);
      const claimed = one[0] ?? two[0]!;
      expect(
        await markOutboxPublished(store, {
          id: "outbox-1",
          leaseToken: "wrong-fence",
          publishedAt: "2026-08-27T12:00:01.000Z",
        }),
      ).toBe(false);
      const afterExpiry = await claimOutboxBatch(store, {
        now: "2026-08-27T12:00:12.000Z",
        leaseUntil: "2026-08-27T12:00:22.000Z",
        limit: 1,
      });
      expect(afterExpiry).toHaveLength(1);
      expect(afterExpiry[0]?.valid).toBe(true);
      if (!afterExpiry[0]?.valid || !claimed.valid) {
        throw new Error("expected valid claims");
      }
      expect(afterExpiry[0].event.data.eventId).toBe(
        claimed.event.data.eventId,
      );
    } finally {
      store.close();
      second.close();
    }
  });

  it("publishes through the official local PubSub and marks success", async () => {
    const { store } = await setup();
    const pubsub = new EventEmitterPubSub();
    const delivered: string[] = [];
    await pubsub.subscribe("security.alert.received", async (event, ack) => {
      delivered.push(event.data.eventId as string);
      await ack?.();
    });
    try {
      const dispatcher = new OutboxDispatcher(
        store,
        pubsub,
        makePhase2Config().outbox,
        silentLogger,
        () => new Date("2026-08-27T12:00:01.000Z"),
      );
      expect(await dispatcher.runOnce()).toBe(1);
      await pubsub.flush();
      expect(delivered).toEqual(["outbox-1"]);
      const row = await store.execute({
        sql: "SELECT published_at, attempt_count FROM outbox_events WHERE id = 'outbox-1'",
      });
      expect(row.rows[0]).toEqual({
        published_at: "2026-08-27T12:00:01.000Z",
        attempt_count: 0,
      });
    } finally {
      await pubsub.close();
      store.close();
    }
  });

  it("backs off confirmed failures and dead-letters at the bounded maximum", async () => {
    const { store } = await setup();
    class FailingPubSub extends EventEmitterPubSub {
      override async publish(): Promise<void> {
        throw new Error("sensitive broker detail");
      }
    }
    const pubsub = new FailingPubSub();
    try {
      for (const timestamp of [
        "2026-08-27T12:00:01.000Z",
        "2026-08-27T12:01:01.000Z",
        "2026-08-27T12:02:01.000Z",
      ]) {
        const dispatcher = new OutboxDispatcher(
          store,
          pubsub,
          { ...makePhase2Config().outbox, maxAttempts: 3 },
          silentLogger,
          () => new Date(timestamp),
        );
        expect(await dispatcher.runOnce()).toBe(1);
      }
      const row = await store.execute({
        sql: `SELECT attempt_count, error_code, published_at,
          (SELECT count(*) FROM dead_letter_events WHERE source_outbox_id = outbox_events.id) AS dead_count
          FROM outbox_events WHERE id = 'outbox-1'`,
      });
      expect(row.rows[0]).toEqual({
        attempt_count: 3,
        error_code: "PUBSUB_UNAVAILABLE",
        published_at: null,
        dead_count: 1,
      });
    } finally {
      await pubsub.close();
      store.close();
    }
  });

  it("recovers a publish-before-marker crash but not a materialized run", async () => {
    const { store } = await setup();
    try {
      const claimed = await claimOutboxBatch(store, {
        now: "2026-08-27T12:00:01.000Z",
        leaseUntil: "2026-08-27T12:00:11.000Z",
        limit: 1,
      });
      await markOutboxPublished(store, {
        id: "outbox-1",
        leaseToken: claimed[0]!.leaseToken,
        publishedAt: "2026-08-27T12:00:02.000Z",
      });
      expect(
        await reconcilePublishedAlertsWithoutRun(store, {
          now: "2026-08-27T12:01:00.000Z",
          olderThan: "2026-08-27T12:00:50.000Z",
        }),
      ).toBe(1);
      const row = await store.execute({
        sql: "SELECT published_at, available_at FROM outbox_events WHERE id = 'outbox-1'",
      });
      expect(row.rows[0]).toEqual({
        published_at: null,
        available_at: "2026-08-27T12:01:00.000Z",
      });
    } finally {
      store.close();
    }
  });

  it("dead-letters a corrupted persisted event instead of poisoning polling", async () => {
    const { store } = await setup();
    const pubsub = new EventEmitterPubSub();
    try {
      await store.execute({
        sql: `UPDATE outbox_events SET payload_json = '{"nested":{"invalid":true}}'
          WHERE id = 'outbox-1'`,
      });
      const dispatcher = new OutboxDispatcher(
        store,
        pubsub,
        { ...makePhase2Config().outbox, maxAttempts: 1 },
        silentLogger,
        () => new Date("2026-08-27T12:00:01.000Z"),
      );
      expect(await dispatcher.runOnce()).toBe(1);
      const result = await store.execute({
        sql: `SELECT error_code, attempt_count,
          (SELECT count(*) FROM dead_letter_events WHERE source_outbox_id = 'outbox-1') AS dead_count
          FROM outbox_events WHERE id = 'outbox-1'`,
      });
      expect(result.rows[0]).toEqual({
        error_code: "EVENT_INVALID",
        attempt_count: 1,
        dead_count: 1,
      });
    } finally {
      await pubsub.close();
      store.close();
    }
  });
});
