import type { Clock } from "../domain/clock.js";
import { systemClock } from "../domain/clock.js";
import { DomainError } from "../domain/errors.js";
import type { IdGenerator } from "../domain/id-generator.js";
import { uuidGenerator } from "../domain/id-generator.js";
import type {
  ExternalIncidentProjection,
  IncidentProvider,
} from "../providers/incident-provider.js";
import {
  ExternalIncidentResultSchema,
  ExternalIncidentSupersededError,
} from "../providers/incident-provider.js";
import type { OperationalStore } from "./operational-store.js";

export type IncidentDeliveryOutcome = Readonly<{
  status: "succeeded" | "retry_scheduled" | "exhausted" | "in_progress";
  externalRef?: string;
  attemptCount: number;
}>;

export async function deliverExternalIncident(
  store: OperationalStore,
  provider: IncidentProvider,
  input: Readonly<{
    operation:
      | "open-awaiting-approval"
      | "decision-rejected"
      | "final-contained"
      | "final-failed";
    projection: ExternalIncidentProjection;
    workflowRunId: string;
    correlationId: string;
    existingExternalRef?: string;
  }>,
  dependencies: Readonly<{
    clock?: Clock;
    ids?: IdGenerator;
    maxAttempts?: number;
    timeoutMs?: number;
  }> = {},
): Promise<IncidentDeliveryOutcome> {
  const clock = dependencies.clock ?? systemClock;
  const ids = dependencies.ids ?? uuidGenerator;
  const maxAttempts = dependencies.maxAttempts ?? 3;
  const timeoutMs = dependencies.timeoutMs ?? 1_000;
  const now = clock.now();
  const idempotencyKey = `mock-incident:${input.projection.incidentId}:${input.operation}`;
  const deliveryId = `delivery_${input.projection.incidentId}_${input.operation}`;
  const claimed = await store.transaction(async (tx) => {
    const incidentGeneration = await tx.execute({
      sql: `SELECT version FROM incidents WHERE tenant_id = ? AND id = ?`,
      args: [input.projection.tenantId, input.projection.incidentId],
    });
    const generation = Number(incidentGeneration.rows[0]?.version);
    if (!Number.isSafeInteger(generation) || generation <= 0) {
      throw new DomainError("CONFLICT");
    }
    await tx.execute({
      sql: `INSERT OR IGNORE INTO provider_deliveries(
        id, provider, incident_id, tenant_id, operation, idempotency_key,
        status, attempt_count, next_attempt_at, projection_json,
        workflow_run_id, correlation_id, provider_generation
      ) VALUES (?, 'mock-incident', ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?, ?)`,
      args: [
        deliveryId,
        input.projection.incidentId,
        input.projection.tenantId,
        input.operation,
        idempotencyKey,
        now,
        JSON.stringify(input.projection),
        input.workflowRunId,
        input.correlationId,
        generation,
      ],
    });
    const current = await tx.execute({
      sql: `SELECT * FROM provider_deliveries
        WHERE provider = 'mock-incident' AND incident_id = ? AND operation = ?`,
      args: [input.projection.incidentId, input.operation],
    });
    const row = current.rows[0];
    if (!row) throw new DomainError("STORAGE_UNAVAILABLE");
    if (
      row.tenant_id !== input.projection.tenantId ||
      row.idempotency_key !== idempotencyKey ||
      row.projection_json !== JSON.stringify(input.projection) ||
      row.workflow_run_id !== input.workflowRunId ||
      !Number.isSafeInteger(Number(row.provider_generation)) ||
      Number(row.provider_generation) <= 0
    ) {
      throw new DomainError("CONFLICT");
    }
    if (row.status === "succeeded") {
      return { state: "succeeded" as const, row };
    }
    if (row.status === "exhausted") {
      return { state: "exhausted" as const, row };
    }
    if (row.status === "delivering" && String(row.next_attempt_at) > now) {
      return { state: "in_progress" as const, row };
    }
    if (input.operation === "final-failed") {
      const authoritative = await tx.execute({
        sql: `SELECT status FROM incidents WHERE tenant_id = ? AND id = ?`,
        args: [input.projection.tenantId, input.projection.incidentId],
      });
      if (
        ["contained", "closed"].includes(String(authoritative.rows[0]?.status))
      ) {
        return { state: "superseded" as const, row };
      }
    }
    let existingExternalRef = input.existingExternalRef;
    if (input.operation !== "open-awaiting-approval" && !existingExternalRef) {
      const opened = await tx.execute({
        sql: `SELECT status, external_ref FROM provider_deliveries
          WHERE provider = 'mock-incident' AND tenant_id = ? AND incident_id = ?
            AND operation = 'open-awaiting-approval'`,
        args: [input.projection.tenantId, input.projection.incidentId],
      });
      if (opened.rows[0]?.status === "exhausted") {
        return { state: "dependency_exhausted" as const, row };
      }
      if (!opened.rows[0]?.external_ref) {
        return { state: "in_progress" as const, row };
      }
      existingExternalRef = String(opened.rows[0].external_ref);
    }
    const leaseUntil = new Date(Date.parse(now) + timeoutMs * 2).toISOString();
    const updated = await tx.execute({
      sql: `UPDATE provider_deliveries SET status = 'delivering',
        attempt_count = attempt_count + 1, next_attempt_at = ?, error_code = NULL
        WHERE id = ? AND attempt_count = ?
          AND status IN ('pending','retry','delivering')
        RETURNING *`,
      args: [leaseUntil, String(row.id), Number(row.attempt_count)],
    });
    return updated.rows[0]
      ? {
          state: "claimed" as const,
          row: updated.rows[0],
          existingExternalRef,
        }
      : { state: "in_progress" as const, row };
  });
  if (claimed.state === "superseded") {
    await persistDeliveryOutcome(
      store,
      input,
      {
        deliveryId: String(claimed.row.id),
        expectedAttempt: Number(claimed.row.attempt_count),
        expectedState: "active",
        status: "exhausted",
        nextAttemptAt: null,
        externalRef: null,
        errorCode: "PROVIDER_DELIVERY_SUPERSEDED",
        auditStatus: "exhausted",
      },
      ids,
      clock,
    );
    return {
      status: "exhausted",
      attemptCount: Number(claimed.row.attempt_count),
    };
  }
  if (claimed.state === "dependency_exhausted") {
    await persistDeliveryOutcome(
      store,
      input,
      {
        deliveryId: String(claimed.row.id),
        expectedAttempt: Number(claimed.row.attempt_count),
        expectedState: "active",
        status: "exhausted",
        nextAttemptAt: null,
        externalRef: null,
        errorCode: "PROVIDER_DEPENDENCY_EXHAUSTED",
        auditStatus: "exhausted",
      },
      ids,
      clock,
    );
    return {
      status: "exhausted",
      attemptCount: Number(claimed.row.attempt_count),
    };
  }
  if (claimed.state !== "claimed") {
    return {
      status: claimed.state,
      ...(claimed.row.external_ref
        ? { externalRef: String(claimed.row.external_ref) }
        : {}),
      attemptCount: Number(claimed.row.attempt_count),
    };
  }
  const attempt = Number(claimed.row.attempt_count);
  const generation = Number(claimed.row.provider_generation);
  if (input.operation === "final-failed") {
    const authoritative = await store.execute({
      sql: `SELECT status FROM incidents WHERE tenant_id = ? AND id = ?`,
      args: [input.projection.tenantId, input.projection.incidentId],
    });
    if (
      ["contained", "closed"].includes(String(authoritative.rows[0]?.status))
    ) {
      await persistDeliveryOutcome(
        store,
        input,
        {
          deliveryId: String(claimed.row.id),
          expectedAttempt: attempt,
          expectedState: "delivering",
          status: "exhausted",
          nextAttemptAt: null,
          externalRef: null,
          errorCode: "PROVIDER_DELIVERY_SUPERSEDED",
          auditStatus: "exhausted",
        },
        ids,
        clock,
      );
      return { status: "exhausted", attemptCount: attempt };
    }
  }
  let delivered: Awaited<ReturnType<IncidentProvider["create"]>>;
  try {
    delivered = ExternalIncidentResultSchema.parse(
      await withTimeout(
        input.operation === "open-awaiting-approval"
          ? provider.create({
              projection: input.projection,
              idempotencyKey,
              generation,
            })
          : provider.update({
              externalRef: claimed.existingExternalRef!,
              projection: input.projection,
              idempotencyKey,
              generation,
            }),
        timeoutMs,
      ),
    );
  } catch (error) {
    if (error instanceof ExternalIncidentSupersededError) {
      await persistDeliveryOutcome(
        store,
        input,
        {
          deliveryId: String(claimed.row.id),
          expectedAttempt: attempt,
          expectedState: "delivering",
          status: "exhausted",
          nextAttemptAt: null,
          externalRef: null,
          errorCode: "PROVIDER_DELIVERY_SUPERSEDED",
          auditStatus: "exhausted",
        },
        ids,
        clock,
      );
      return { status: "exhausted", attemptCount: attempt };
    }
    const exhausted = attempt >= maxAttempts;
    const errorCode =
      error instanceof TimeoutError
        ? "PROVIDER_TIMEOUT"
        : "PROVIDER_UNAVAILABLE";
    const nextAttemptAt = exhausted
      ? null
      : new Date(Date.parse(now) + 250 * 2 ** (attempt - 1)).toISOString();
    await persistDeliveryOutcome(
      store,
      input,
      {
        deliveryId: String(claimed.row.id),
        expectedAttempt: attempt,
        expectedState: "delivering",
        status: exhausted ? "exhausted" : "retry",
        nextAttemptAt,
        externalRef: null,
        errorCode,
        auditStatus: exhausted ? "exhausted" : "retry_scheduled",
      },
      ids,
      clock,
    );
    return {
      status: exhausted ? "exhausted" : "retry_scheduled",
      attemptCount: attempt,
    };
  }
  try {
    await persistDeliveryOutcome(
      store,
      input,
      {
        deliveryId: String(claimed.row.id),
        expectedAttempt: attempt,
        expectedState: "delivering",
        status: "succeeded",
        nextAttemptAt: null,
        externalRef: delivered.externalRef,
        errorCode: null,
        auditStatus: "succeeded",
      },
      ids,
      clock,
    );
  } catch {
    const reconciled = await store.execute({
      sql: `SELECT status, external_ref FROM provider_deliveries WHERE id = ?`,
      args: [String(claimed.row.id)],
    });
    if (
      reconciled.rows[0]?.status === "succeeded" &&
      reconciled.rows[0].external_ref === delivered.externalRef
    ) {
      return {
        status: "succeeded",
        externalRef: delivered.externalRef,
        attemptCount: attempt,
      };
    }
    throw new DomainError("STORAGE_UNAVAILABLE", { retryable: true });
  }
  return {
    status: "succeeded",
    externalRef: delivered.externalRef,
    attemptCount: attempt,
  };
}

async function persistDeliveryOutcome(
  store: OperationalStore,
  input: Parameters<typeof deliverExternalIncident>[2],
  outcome: Readonly<{
    deliveryId: string;
    expectedAttempt: number;
    expectedState: "active" | "delivering";
    status: "succeeded" | "retry" | "exhausted";
    nextAttemptAt: string | null;
    externalRef: string | null;
    errorCode: string | null;
    auditStatus: "succeeded" | "retry_scheduled" | "exhausted";
  }>,
  ids: IdGenerator,
  clock: Clock,
): Promise<void> {
  const occurredAt = clock.now();
  await store.transaction(async (tx) => {
    const updated = await tx.execute({
      sql: `UPDATE provider_deliveries SET status = ?, next_attempt_at = ?,
        external_ref = ?, error_code = ? WHERE id = ? AND attempt_count = ?
        AND ${outcome.expectedState === "delivering" ? "status = 'delivering'" : "status IN ('pending','retry','delivering')"}`,
      args: [
        outcome.status,
        outcome.nextAttemptAt,
        outcome.externalRef,
        outcome.errorCode,
        outcome.deliveryId,
        outcome.expectedAttempt,
      ],
    });
    if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
    const incident = await tx.execute({
      sql: `UPDATE incidents SET timeline_sequence = timeline_sequence + 1,
        updated_at = ? WHERE tenant_id = ? AND id = ? AND updated_at <= ?
        RETURNING timeline_sequence`,
      args: [
        occurredAt,
        input.projection.tenantId,
        input.projection.incidentId,
        occurredAt,
      ],
    });
    if (!incident.rows[0]) throw new DomainError("CONFLICT");
    await tx.execute({
      sql: `INSERT INTO timeline_events(
        id, incident_id, tenant_id, sequence, type, category, correlation_id,
        causation_id, payload_json, schema_version, occurred_at
      ) VALUES (?, ?, ?, ?, 'provider.incident_delivery', 'domain', ?, ?, ?, 1, ?)`,
      args: [
        ids.next(),
        input.projection.incidentId,
        input.projection.tenantId,
        Number(incident.rows[0].timeline_sequence),
        input.correlationId,
        input.workflowRunId,
        JSON.stringify({
          provider: "mock-incident",
          operation: input.operation,
          status: outcome.auditStatus,
          attempt: outcome.expectedAttempt,
          ...(outcome.errorCode ? { errorCode: outcome.errorCode } : {}),
        }),
        occurredAt,
      ],
    });
  });
}

class TimeoutError extends Error {}

async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new TimeoutError()), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
