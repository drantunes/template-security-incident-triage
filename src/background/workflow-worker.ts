import type { PubSub } from "@mastra/core/events";
import { createHash } from "node:crypto";
import { z } from "zod";

import type { OperationalStore } from "../db/operational-store.js";
import {
  hasUnresolvedOutboxDeadLetter,
  persistOutboxDeadLetter,
} from "../db/outbox-operations.js";
import {
  hasWorkflowRun,
  INCIDENT_INGESTION_WORKFLOW_ID,
  type StartInvestigationInput,
} from "../db/workflow-run-operations.js";
import { persistStandaloneDeadLetter } from "../db/webhook-operations.js";
import { persistRedisDecodeFailure } from "../db/redis-decode-failure-operations.js";
import type { StructuredLogger } from "../logging.js";
import { DomainEventSchema } from "../schemas/domain-event.js";
import { opaqueId } from "../schemas/common.js";
import { createPhase4TraceCarrier } from "../mastra/observability.js";

const workerEventSchema = DomainEventSchema.extend({
  type: z.literal("security.alert.received"),
  data: DomainEventSchema.shape.data.extend({
    payload: z.object({ alertId: opaqueId }).passthrough(),
  }),
});

type WorkflowRun = Readonly<{
  startAsync(input: {
    inputData: StartInvestigationInput;
    requestContext?: ReturnType<
      typeof createPhase4TraceCarrier
    >["requestContext"];
    tracingOptions?: ReturnType<
      typeof createPhase4TraceCarrier
    >["tracingOptions"];
  }): Promise<{ runId: string }>;
}>;

export interface IngestionWorkflow {
  createRun(options: {
    runId: string;
    resourceId: string;
  }): Promise<WorkflowRun>;
}

/**
 * Signals the vendored Redis Streams adapter to retain its current PEL entry.
 * It deliberately is not a retry/nack: no replacement entry is published and
 * the adapter must not consume its terminal-delivery budget until local poison
 * persistence has committed.
 */
export class RetainPubSubDeliveryError extends Error {
  readonly code = "PHASE8_RETAIN_DELIVERY";

  constructor() {
    super("Retain delivery until durable poison persistence succeeds.");
    this.name = "RetainPubSubDeliveryError";
  }
}

export async function startWorkflowWorker(
  input: Readonly<{
    pubsub: PubSub;
    workflow: IngestionWorkflow;
    store: OperationalStore;
    logger: StructuredLogger;
    maxAttempts: number;
    retryBackoffMs?: readonly number[];
    concurrency?: number;
    random?: () => number;
    schedule?: (delayMs: number) => Promise<void>;
  }>,
): Promise<() => Promise<void>> {
  const callback = async (
    delivered: Parameters<Parameters<PubSub["subscribe"]>[1]>[0],
    ack?: () => Promise<void>,
    nack?: () => Promise<void>,
  ) => {
    const parsed = workerEventSchema.safeParse({
      type: delivered.type,
      runId: delivered.runId,
      data: delivered.data,
    });
    if (!parsed.success) {
      // Redis has already decoded this transport record, but it is still
      // untrusted input. Persist its hash/size plus a standalone DLQ and the
      // canonical security.dead-letter outbox event in *one* transaction
      // before ACK. No source outbox id is authority for malformed input.
      await persistTransportPoisonOrRetain(input.store, delivered);
      input.logger.write({
        event: "worker.dead_lettered",
        errorCode: "EVENT_INVALID",
      });
      await ack?.();
      return;
    }
    const event = parsed.data;
    // A syntactically valid Redis payload is still untrusted transport input.
    // Bind it to the authoritative outbox envelope before claiming, starting,
    // or ACKing any effect; a copied eventId must not execute another tenant's
    // source entry.
    if (
      !(await matchesOutboxEnvelope(input.store, delivered, event.data.eventId))
    ) {
      await persistTransportPoisonOrRetain(input.store, delivered);
      input.logger.write({
        event: "worker.dead_lettered",
        errorCode: "EVENT_INVALID",
      });
      // This delivery copied an authoritative event id but failed the complete
      // envelope binding. The standalone DLQ commit above is its terminal
      // record; it must not stay pending forever or mutate the copied source
      // ledger/outbox.
      await ack?.();
      return;
    }
    const effect = await claimConsumerEffect(input.store, event.data.eventId);
    if (effect.state === "terminal" || effect.state === "busy") {
      input.logger.write({
        event: "worker.no_op",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: event.data.eventId,
      });
      // A busy claimant still owns the delivery.  ACKing a reclaimed entry
      // here would erase it from the PEL while the original effect is live.
      if (effect.state === "terminal") await ack?.();
      return;
    }
    if (await hasUnresolvedOutboxDeadLetter(input.store, event.data.eventId)) {
      input.logger.write({
        event: "worker.no_op",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: event.data.eventId,
        errorCode: "WORKFLOW_START_FAILED",
      });
      const terminal = await deadLetterConsumerEffect(
        input.store,
        event.data.eventId,
        effect.attemptCount,
        effect.fenceToken,
      );
      if (terminal) await ack?.();
      return;
    }
    if (await hasWorkflowRun(input.store, event.data.eventId)) {
      input.logger.write({
        event: "worker.no_op",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: event.data.eventId,
      });
      const completed = await completeConsumerEffect(
        input.store,
        event.data.eventId,
        effect.attemptCount,
        effect.fenceToken,
      );
      if (completed) await ack?.();
      return;
    }
    try {
      const run = await input.workflow.createRun({
        runId: event.data.eventId,
        resourceId: event.data.incidentId,
      });
      const traceCarrier = createPhase4TraceCarrier({
        tenantId: event.data.tenantId,
        incidentId: event.data.incidentId,
        runId: event.data.eventId,
        correlationId: event.data.correlationId,
      });
      const started = await run.startAsync({
        inputData: {
          eventId: event.data.eventId,
          incidentId: event.data.incidentId,
          tenantId: event.data.tenantId,
          alertId: event.data.payload.alertId,
          correlationId: event.data.correlationId,
        },
        ...traceCarrier,
      });
      input.logger.write({
        event: "worker.started",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: started.runId,
      });
      const completed = await completeConsumerEffect(
        input.store,
        event.data.eventId,
        effect.attemptCount,
        effect.fenceToken,
      );
      if (completed) await ack?.();
    } catch {
      const attempt = effect.attemptCount;
      if (attempt < input.maxAttempts && nack) {
        input.logger.write({
          event: "worker.retry",
          correlationId: event.data.correlationId,
          incidentId: event.data.incidentId,
          errorCode: "WORKFLOW_START_FAILED",
          attempt,
        });
        const cap =
          input.retryBackoffMs?.[attempt - 1] ?? 500 * 2 ** (attempt - 1);
        // RedisStreamsPubSub nacks immediately. Keep the message pending until
        // the policy scheduler releases it so each redelivery observes the
        // approved capped full-jitter delay instead of a hot retry loop.
        const jitter = Math.min(
          1,
          Math.max(0, (input.random ?? Math.random)()),
        );
        await (input.schedule ?? delay)(Math.floor(cap * jitter));
        await releaseConsumerEffect(
          input.store,
          event.data.eventId,
          attempt,
          effect.fenceToken,
        );
        await nack();
        return;
      }
      const terminal = await persistOutboxDeadLetter(input.store, {
        outboxId: event.data.eventId,
        errorCode: "WORKFLOW_START_FAILED",
        attemptCount: attempt,
        createdAt: new Date().toISOString(),
      });
      if (terminal === "outbox_missing") {
        await persistStandaloneDeadLetter(input.store, {
          eventType: event.type,
          eventRef: `event:${event.data.eventId}`,
          errorCode: "WORKFLOW_START_FAILED",
          tenantId: event.data.tenantId,
          incidentId: event.data.incidentId,
        });
      }
      input.logger.write({
        event:
          terminal === "workflow_run_exists"
            ? "worker.no_op"
            : "worker.dead_lettered",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        errorCode: "WORKFLOW_START_FAILED",
        attempt,
      });
      const deadLettered = await deadLetterConsumerEffect(
        input.store,
        event.data.eventId,
        attempt,
        effect.fenceToken,
      );
      if (deadLettered) await ack?.();
    }
  };
  const subscribers = Math.max(1, Math.min(16, input.concurrency ?? 1));
  const semaphore = createSemaphore(subscribers);
  const callbacks = Array.from(
    { length: subscribers },
    () =>
      async (...args: Parameters<typeof callback>) =>
        semaphore.run(() => callback(...args)),
  );
  await Promise.all(
    callbacks.map((subscriber) =>
      input.pubsub.subscribe("security.alert.received", subscriber, {
        group: "security-workflow-starters",
      }),
    ),
  );
  return async () => {
    await Promise.all(
      callbacks.map((subscriber) =>
        input.pubsub.unsubscribe("security.alert.received", subscriber),
      ),
    );
  };
}

/**
 * A parsed but non-authoritative envelope is poison at the Redis transport
 * boundary.  The serialized value is used only to calculate hash/size, then
 * discarded; the database receives no raw event data or tenant supplied PII.
 */
async function persistTransportPoison(
  store: OperationalStore,
  delivered: Readonly<{
    id?: unknown;
    type?: unknown;
    runId?: unknown;
    data?: unknown;
  }>,
): Promise<void> {
  const bytes = new TextEncoder().encode(
    canonicalJson({
      id: delivered.id ?? null,
      type: delivered.type ?? null,
      runId: delivered.runId ?? null,
      data: delivered.data ?? null,
    }),
  );
  const payloadHash = createHash("sha256").update(bytes).digest("hex");
  // A transport id alone is not an event identity: a producer can reuse it
  // (or an invalid envelope can copy it). Bind the synthetic transport
  // identity to the complete byte digest so same-size payloads cannot share a
  // failure row, terminal DLQ, or outbox event. The digest—not raw bytes—is
  // the only payload-derived value retained after this function returns.
  const streamId = `transport-${createStableDigest(
    canonicalJson({
      topic: "security.alert.received",
      transportId: delivered.id ?? null,
      payloadHash,
    }),
  )}`;
  await persistRedisDecodeFailure(store, {
    topic: "security.alert.received",
    streamId,
    group: "security-workflow-starters",
    consumer: "workflow-worker",
    rawBytes: bytes,
    errorCode: "EVENT_INVALID",
  });
}

async function persistTransportPoisonOrRetain(
  store: OperationalStore,
  delivered: Readonly<{
    id?: unknown;
    type?: unknown;
    runId?: unknown;
    data?: unknown;
  }>,
): Promise<void> {
  try {
    await persistTransportPoison(store, delivered);
  } catch {
    // Keep the original error (which may carry operational details) out of
    // logs/transport. The patched adapter recognizes this closed signal.
    throw new RetainPubSubDeliveryError();
  }
}

function createStableDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * A malformed body may still carry an `eventId`; it is not authority by
 * itself. Bind every envelope field to the source outbox row before a worker
 * can dead-letter that source or change its consumer ledger.
 */
async function matchesOutboxEnvelope(
  store: OperationalStore,
  delivered: Readonly<{ type?: unknown; runId?: unknown; data?: unknown }>,
  eventId: string,
): Promise<boolean> {
  const data = delivered.data;
  if (!data || typeof data !== "object") return false;
  const raw = data as Record<string, unknown>;
  const row = await store.execute({
    sql: `SELECT type, run_id, incident_id, tenant_id, schema_version, correlation_id,
      causation_id, payload_json, occurred_at
      FROM outbox_events WHERE id = ?`,
    args: [eventId],
  });
  const source = row.rows[0];
  return Boolean(
    source &&
    delivered.type === source.type &&
    delivered.runId === source.run_id &&
    raw.incidentId === source.incident_id &&
    raw.tenantId === source.tenant_id &&
    raw.schemaVersion === source.schema_version &&
    raw.correlationId === source.correlation_id &&
    raw.occurredAt === source.occurred_at &&
    (raw.causationId ?? null) === source.causation_id &&
    canonicalJson(raw.payload) ===
      canonicalJson(JSON.parse(String(source.payload_json))),
  );
}

function canonicalJson(value: unknown): string {
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object")
      return Object.fromEntries(
        Object.entries(item as Record<string, unknown>)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, child]) => [key, normalize(child)]),
      );
    return item;
  };
  return JSON.stringify(normalize(value));
}

function delay(delayMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

function createSemaphore(limit: number) {
  let active = 0;
  const waiting: Array<() => void> = [];
  return {
    async run<T>(operation: () => Promise<T>): Promise<T> {
      if (active >= limit)
        await new Promise<void>((resolve) => waiting.push(resolve));
      active += 1;
      try {
        return await operation();
      } finally {
        active -= 1;
        waiting.shift()?.();
      }
    },
  };
}

async function claimConsumerEffect(
  store: OperationalStore,
  eventId: string,
): Promise<
  Readonly<{
    state: "acquired" | "busy" | "terminal";
    attemptCount: number;
    fenceToken: string;
  }>
> {
  const now = new Date();
  const nowIso = now.toISOString();
  const lease = new Date(now.getTime() + 60_000).toISOString();
  return store.transaction(async (tx) => {
    const current = await tx.execute({
      sql: `SELECT status, attempt_count, lease_expires_at FROM consumer_effect_ledger
        WHERE consumer_group = 'security-workflow-starters' AND event_id = ?`,
      args: [eventId],
    });
    const row = current.rows[0];
    if (row && ["completed", "dead_lettered"].includes(String(row.status)))
      return {
        state: "terminal",
        attemptCount: Number(row.attempt_count),
        fenceToken: String(row.fence_token),
      };
    if (row && String(row.lease_expires_at) > nowIso)
      return {
        state: "busy",
        attemptCount: Number(row.attempt_count),
        fenceToken: String(row.fence_token),
      };
    const attempt = Number(row?.attempt_count ?? 0) + 1;
    if (row) {
      const updated = await tx.execute({
        sql: `UPDATE consumer_effect_ledger SET status = 'processing', attempt_count = ?,
          fence_token = ?, lease_expires_at = ?, completed_at = NULL
          WHERE consumer_group = 'security-workflow-starters' AND event_id = ?
            AND lease_expires_at <= ? AND status = 'processing'`,
        args: [attempt, `worker:${eventId}:${attempt}`, lease, eventId, nowIso],
      });
      if (updated.rowsAffected !== 1)
        return {
          state: "busy",
          attemptCount: attempt,
          fenceToken: String(row.fence_token),
        };
    } else {
      await tx.execute({
        sql: `INSERT INTO consumer_effect_ledger(
          consumer_group, event_id, status, attempt_count, fence_token, lease_expires_at
        ) VALUES ('security-workflow-starters', ?, 'processing', ?, ?, ?)`,
        args: [eventId, attempt, `worker:${eventId}:${attempt}`, lease],
      });
    }
    return {
      state: "acquired",
      attemptCount: attempt,
      fenceToken: `worker:${eventId}:${attempt}`,
    };
  });
}

async function releaseConsumerEffect(
  store: OperationalStore,
  eventId: string,
  attemptCount: number,
  fenceToken: string,
): Promise<void> {
  await store.execute({
    sql: `UPDATE consumer_effect_ledger SET lease_expires_at = ?
      WHERE consumer_group = 'security-workflow-starters' AND event_id = ?
        AND status = 'processing' AND attempt_count = ? AND fence_token = ?`,
    args: [new Date(0).toISOString(), eventId, attemptCount, fenceToken],
  });
}

async function completeConsumerEffect(
  store: OperationalStore,
  eventId: string,
  attemptCount: number,
  fenceToken: string,
): Promise<boolean> {
  const now = new Date().toISOString();
  const updated = await store.execute({
    sql: `UPDATE consumer_effect_ledger SET status = 'completed', completed_at = ?, lease_expires_at = ?
      WHERE consumer_group = 'security-workflow-starters' AND event_id = ?
        AND status = 'processing' AND attempt_count = ? AND fence_token = ?`,
    args: [now, now, eventId, attemptCount, fenceToken],
  });
  return updated.rowsAffected === 1;
}

async function deadLetterConsumerEffect(
  store: OperationalStore,
  eventId: string,
  attemptCount: number,
  fenceToken: string,
): Promise<boolean> {
  const now = new Date().toISOString();
  const updated = await store.execute({
    sql: `UPDATE consumer_effect_ledger SET status = 'dead_lettered', completed_at = ?, lease_expires_at = ?
      WHERE consumer_group = 'security-workflow-starters' AND event_id = ?
        AND status = 'processing' AND attempt_count = ? AND fence_token = ?`,
    args: [now, now, eventId, attemptCount, fenceToken],
  });
  return updated.rowsAffected === 1;
}

export { INCIDENT_INGESTION_WORKFLOW_ID };
