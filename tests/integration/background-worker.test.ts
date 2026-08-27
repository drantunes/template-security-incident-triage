import { EventEmitterPubSub, PubSub } from "@mastra/core/events";
import type { Event, EventCallback } from "@mastra/core/events";
import { afterEach, describe, expect, it } from "vitest";

import { startWorkflowWorker } from "../../src/background/workflow-worker.js";
import { createIncidentFromAlert } from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import type { OperationalStore } from "../../src/db/operational-store.js";
import {
  claimOutboxBatch,
  markOutboxPublished,
  persistOutboxDeadLetter,
  reconcilePublishedAlertsWithoutRun,
} from "../../src/db/outbox-operations.js";
import {
  hasWorkflowRun,
  materializeInvestigationStart,
} from "../../src/db/workflow-run-operations.js";
import { fixedClock } from "../../src/domain/clock.js";
import { sequenceIdGenerator } from "../../src/domain/id-generator.js";
import { makeAlert } from "../fixtures/domain.js";
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

describe("background workflow start", () => {
  it("materializes one logical effect under concurrent starts", async () => {
    const { database, store } = await setup();
    const second = database.createStore();
    const input = {
      eventId: "outbox-1",
      incidentId: "incident-1",
      tenantId: "tenant-1",
      alertId: "alert-1",
      correlationId: "correlation-1",
    };
    try {
      const results = await Promise.all([
        materializeInvestigationStart(store, input, {
          clock: fixedClock("2026-08-27T12:00:01.000Z"),
          ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
        }),
        materializeInvestigationStart(second, input, {
          clock: fixedClock("2026-08-27T12:00:01.000Z"),
          ids: sequenceIdGenerator(["timeline-3", "outbox-3"]),
        }),
      ]);
      expect(results.map((result) => result.duplicate).sort()).toEqual([
        false,
        true,
      ]);
      const state = await store.execute({
        sql: `SELECT status, current_run_id, version, timeline_sequence,
          (SELECT count(*) FROM workflow_runs) AS run_count,
          (SELECT count(*) FROM timeline_events) AS timeline_count
          FROM incidents WHERE id = 'incident-1'`,
      });
      expect(state.rows[0]).toEqual({
        status: "investigating",
        current_run_id: "outbox-1",
        version: 1,
        timeline_sequence: 2,
        run_count: 1,
        timeline_count: 2,
      });
    } finally {
      store.close();
      second.close();
    }
  });

  it("subscribes through official PubSub, starts asynchronously and no-ops a retry", async () => {
    const { store } = await setup();
    const pubsub = new EventEmitterPubSub();
    let starts = 0;
    let resolveStarted = () => {};
    const started = new Promise<void>((resolve) => {
      resolveStarted = resolve;
    });
    let resolveNoOp = () => {};
    const noOp = new Promise<void>((resolve) => {
      resolveNoOp = resolve;
    });
    const workflow = {
      createRun: async () => ({
        startAsync: async ({
          inputData,
        }: {
          inputData: Parameters<typeof materializeInvestigationStart>[1];
        }) => {
          starts += 1;
          await materializeInvestigationStart(store, inputData, {
            clock: fixedClock("2026-08-27T12:00:01.000Z"),
            ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
          });
          resolveStarted();
          return { runId: inputData.eventId };
        },
      }),
    };
    const unsubscribe = await startWorkflowWorker({
      pubsub,
      workflow,
      store,
      logger: {
        write: (record) => {
          if (record.event === "worker.no_op") resolveNoOp();
        },
      },
      maxAttempts: 3,
    });
    const event = {
      type: "security.alert.received",
      runId: "incident-1",
      data: {
        eventId: "outbox-1",
        schemaVersion: 1,
        occurredAt: "2026-08-27T12:00:00.000Z",
        incidentId: "incident-1",
        tenantId: "tenant-1",
        correlationId: "correlation-1",
        causationId: "source-event-1",
        payload: { alertId: "alert-1", status: "received" },
      },
    };
    try {
      await pubsub.publish(event.type, event);
      await started;
      expect(await hasWorkflowRun(store, "outbox-1")).toBe(true);
      await pubsub.publish(event.type, event);
      await noOp;
      expect(starts).toBe(1);
    } finally {
      await unsubscribe();
      await pubsub.close();
      store.close();
    }
  });

  it("dead-letters an invalid event without starting a workflow", async () => {
    const { store } = await setup();
    const pubsub = new EventEmitterPubSub();
    let starts = 0;
    const unsubscribe = await startWorkflowWorker({
      pubsub,
      workflow: {
        createRun: async () => {
          starts += 1;
          throw new Error("must not start");
        },
      },
      store,
      logger: silentLogger,
      maxAttempts: 3,
    });
    try {
      await pubsub.publish("security.alert.received", {
        type: "security.alert.received",
        runId: "incident-1",
        data: { schemaVersion: 2 },
      });
      await pubsub.flush();
      const count = await store.execute({
        sql: "SELECT count(*) AS count FROM dead_letter_events",
      });
      expect(Number(count.rows[0]?.count)).toBe(1);
      expect(starts).toBe(0);
    } finally {
      await unsubscribe();
      await pubsub.close();
      store.close();
    }
  });

  it("nacks transient workflow failures and dead-letters at the worker budget", async () => {
    const { store } = await setup();
    class CapturingPubSub extends PubSub {
      callback?: EventCallback;
      override async publish(): Promise<void> {}
      override async subscribe(
        _topic: string,
        callback: EventCallback,
      ): Promise<void> {
        this.callback = callback;
      }
      override async unsubscribe(): Promise<void> {
        this.callback = undefined;
      }
      override async flush(): Promise<void> {}
      async deliver(
        event: Event,
        ack: () => Promise<void>,
        nack: () => Promise<void>,
      ) {
        await this.callback?.(event, ack, nack);
      }
    }
    const pubsub = new CapturingPubSub();
    const unsubscribe = await startWorkflowWorker({
      pubsub,
      workflow: {
        createRun: async () => {
          throw new Error("transient detail");
        },
      },
      store,
      logger: silentLogger,
      maxAttempts: 3,
    });
    const baseEvent: Event = {
      id: "transport-1",
      createdAt: new Date(),
      type: "security.alert.received",
      runId: "incident-1",
      data: {
        eventId: "outbox-1",
        schemaVersion: 1,
        occurredAt: "2026-08-27T12:00:00.000Z",
        incidentId: "incident-1",
        tenantId: "tenant-1",
        correlationId: "correlation-1",
        payload: { alertId: "alert-1" },
      },
    };
    let acknowledgements = 0;
    let negativeAcknowledgements = 0;
    const ack = async () => {
      acknowledgements += 1;
    };
    const nack = async () => {
      negativeAcknowledgements += 1;
    };
    try {
      await pubsub.deliver({ ...baseEvent, deliveryAttempt: 1 }, ack, nack);
      expect({ acknowledgements, negativeAcknowledgements }).toEqual({
        acknowledgements: 0,
        negativeAcknowledgements: 1,
      });
      await pubsub.deliver({ ...baseEvent, deliveryAttempt: 3 }, ack, nack);
      expect({ acknowledgements, negativeAcknowledgements }).toEqual({
        acknowledgements: 1,
        negativeAcknowledgements: 1,
      });
      const dead = await store.execute({
        sql: "SELECT error_code FROM dead_letter_events",
      });
      expect(dead.rows).toEqual([{ error_code: "WORKFLOW_START_FAILED" }]);
    } finally {
      await unsubscribe();
      store.close();
    }
  });

  it("keeps a worker-exhausted outbox event terminal during reconciliation and redelivery", async () => {
    const { store } = await setup();
    class CapturingPubSub extends PubSub {
      callback?: EventCallback;
      override async publish(): Promise<void> {}
      override async subscribe(
        _topic: string,
        callback: EventCallback,
      ): Promise<void> {
        this.callback = callback;
      }
      override async unsubscribe(): Promise<void> {
        this.callback = undefined;
      }
      override async flush(): Promise<void> {}
      async deliver(event: Event, ack: () => Promise<void>) {
        await this.callback?.(event, ack);
      }
    }
    const claimed = await claimOutboxBatch(store, {
      now: "2026-08-27T12:00:00.000Z",
      leaseUntil: "2026-08-27T12:00:10.000Z",
      limit: 1,
    });
    await markOutboxPublished(store, {
      id: "outbox-1",
      leaseToken: claimed[0]!.leaseToken,
      publishedAt: "2026-08-27T12:00:01.000Z",
    });
    const pubsub = new CapturingPubSub();
    let createRuns = 0;
    const unsubscribe = await startWorkflowWorker({
      pubsub,
      workflow: {
        createRun: async () => {
          createRuns += 1;
          return {
            startAsync: async () => {
              if (createRuns === 1) {
                throw new Error("permanent start failure");
              }
              await materializeInvestigationStart(
                store,
                {
                  eventId: "outbox-1",
                  incidentId: "incident-1",
                  tenantId: "tenant-1",
                  alertId: "alert-1",
                  correlationId: "correlation-1",
                },
                {
                  clock: fixedClock("2026-08-27T12:00:02.000Z"),
                  ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
                },
              );
              return { runId: "outbox-1" };
            },
          };
        },
      },
      store,
      logger: silentLogger,
      maxAttempts: 1,
    });
    const event: Event = {
      id: "transport-1",
      createdAt: new Date(),
      deliveryAttempt: 1,
      type: "security.alert.received",
      runId: "incident-1",
      data: {
        eventId: "outbox-1",
        schemaVersion: 1,
        occurredAt: "2026-08-27T12:00:00.000Z",
        incidentId: "incident-1",
        tenantId: "tenant-1",
        correlationId: "correlation-1",
        payload: { alertId: "alert-1" },
      },
    };
    let acknowledgements = 0;
    try {
      await pubsub.deliver(event, async () => {
        acknowledgements += 1;
      });
      expect(acknowledgements).toBe(1);
      const dead = await store.execute({
        sql: `SELECT source_outbox_id, error_code, attempt_count
          FROM dead_letter_events`,
      });
      expect(dead.rows).toEqual([
        {
          source_outbox_id: "outbox-1",
          error_code: "WORKFLOW_START_FAILED",
          attempt_count: 1,
        },
      ]);
      expect(
        await reconcilePublishedAlertsWithoutRun(store, {
          now: "2026-08-27T12:01:00.000Z",
          olderThan: "2026-08-27T12:00:50.000Z",
        }),
      ).toBe(0);
      const outbox = await store.execute({
        sql: "SELECT published_at FROM outbox_events WHERE id = 'outbox-1'",
      });
      expect(outbox.rows[0]?.published_at).toBe("2026-08-27T12:00:01.000Z");
      await pubsub.deliver({ ...event, id: "transport-2" }, async () => {
        acknowledgements += 1;
      });
      expect(acknowledgements).toBe(2);
      expect(createRuns).toBe(1);
      const state = await store.execute({
        sql: `SELECT status,
          (SELECT count(*) FROM workflow_runs) AS runs,
          (SELECT count(*) FROM dead_letter_events) AS dead_letters
          FROM incidents WHERE id = 'incident-1'`,
      });
      expect(state.rows[0]).toEqual({
        status: "received",
        runs: 0,
        dead_letters: 1,
      });
    } finally {
      await unsubscribe();
      store.close();
    }
  });

  it("serializes terminal dead-letter and first-step materialization without contradictory state", async () => {
    const { database, store } = await setup();
    const materializationStore = database.createStore();
    let releaseMaterialization = () => {};
    const mayMaterialize = new Promise<void>((resolve) => {
      releaseMaterialization = resolve;
    });
    let signalMaterialization = () => {};
    const materializationStarted = new Promise<void>((resolve) => {
      signalMaterialization = resolve;
    });
    const delayedStore: OperationalStore = {
      execute: (statement) => materializationStore.execute(statement),
      transaction: async (fn) => {
        signalMaterialization();
        await mayMaterialize;
        return materializationStore.transaction(fn);
      },
      close: () => materializationStore.close(),
    };
    const input = {
      eventId: "outbox-1",
      incidentId: "incident-1",
      tenantId: "tenant-1",
      alertId: "alert-1",
      correlationId: "correlation-1",
    };
    try {
      const materializing = materializeInvestigationStart(delayedStore, input, {
        clock: fixedClock("2026-08-27T12:00:01.000Z"),
        ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
      });
      await materializationStarted;
      expect(
        await persistOutboxDeadLetter(store, {
          outboxId: "outbox-1",
          errorCode: "WORKFLOW_START_FAILED",
          attemptCount: 1,
          createdAt: "2026-08-27T12:00:01.000Z",
        }),
      ).toBe("dead_letter");
      releaseMaterialization();
      expect(await materializing).toEqual({
        duplicate: true,
        runId: "outbox-1",
      });
      const terminalWins = await store.execute({
        sql: `SELECT status,
          (SELECT count(*) FROM workflow_runs) AS runs,
          (SELECT count(*) FROM dead_letter_events) AS dead_letters
          FROM incidents WHERE id = 'incident-1'`,
      });
      expect(terminalWins.rows[0]).toEqual({
        status: "received",
        runs: 0,
        dead_letters: 1,
      });
    } finally {
      releaseMaterialization();
      delayedStore.close();
      store.close();
    }

    const secondSetup = await setup();
    try {
      await materializeInvestigationStart(secondSetup.store, input, {
        clock: fixedClock("2026-08-27T12:00:01.000Z"),
        ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
      });
      expect(
        await persistOutboxDeadLetter(secondSetup.store, {
          outboxId: "outbox-1",
          errorCode: "WORKFLOW_START_FAILED",
          attemptCount: 1,
          createdAt: "2026-08-27T12:00:02.000Z",
        }),
      ).toBe("workflow_run_exists");
      const markerWins = await secondSetup.store.execute({
        sql: `SELECT status,
          (SELECT count(*) FROM workflow_runs) AS runs,
          (SELECT count(*) FROM dead_letter_events) AS dead_letters
          FROM incidents WHERE id = 'incident-1'`,
      });
      expect(markerWins.rows[0]).toEqual({
        status: "investigating",
        runs: 1,
        dead_letters: 0,
      });
    } finally {
      secondSetup.store.close();
    }
  });
});
