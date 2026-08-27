import { systemClock, type Clock } from "../domain/clock.js";
import { DomainError } from "../domain/errors.js";
import { uuidGenerator, type IdGenerator } from "../domain/id-generator.js";
import { insertTimelineAndOutbox } from "./incident-operations.js";
import type { OperationalStore } from "./operational-store.js";

export const INCIDENT_INGESTION_WORKFLOW_ID = "incident-ingestion-workflow";

export type StartInvestigationInput = Readonly<{
  eventId: string;
  incidentId: string;
  tenantId: string;
  alertId: string;
  correlationId: string;
}>;

export async function materializeInvestigationStart(
  store: OperationalStore,
  input: StartInvestigationInput,
  dependencies: Readonly<{ clock?: Clock; ids?: IdGenerator }> = {},
): Promise<Readonly<{ duplicate: boolean; runId: string }>> {
  const clock = dependencies.clock ?? systemClock;
  const ids = dependencies.ids ?? uuidGenerator;
  const now = clock.now();
  try {
    return await store.transaction(async (tx) => {
      const terminal = await tx.execute({
        sql: `SELECT 1 FROM dead_letter_events
          WHERE source_outbox_id = ? AND resolved_at IS NULL`,
        args: [input.eventId],
      });
      if (terminal.rows.length > 0) {
        return { duplicate: true, runId: input.eventId };
      }
      const existing = await tx.execute({
        sql: `SELECT incident_id, tenant_id, workflow_id FROM workflow_runs
          WHERE run_id = ?`,
        args: [input.eventId],
      });
      if (existing.rows[0]) {
        assertEquivalentMarker(existing.rows[0], input);
        return { duplicate: true, runId: input.eventId };
      }
      const current = await tx.execute({
        sql: `SELECT status, current_run_id, timeline_sequence FROM incidents
          WHERE tenant_id = ? AND id = ?`,
        args: [input.tenantId, input.incidentId],
      });
      const incident = current.rows[0];
      if (!incident) throw new DomainError("NOT_FOUND");
      if (incident.status !== "received") {
        throw new DomainError("CONFLICT");
      }
      await tx.execute({
        sql: `INSERT INTO workflow_runs(
          id, incident_id, tenant_id, run_id, workflow_id, status, started_at
        ) VALUES (?, ?, ?, ?, ?, 'running', ?)`,
        args: [
          input.eventId,
          input.incidentId,
          input.tenantId,
          input.eventId,
          INCIDENT_INGESTION_WORKFLOW_ID,
          now,
        ],
      });
      const updated = await tx.execute({
        sql: `UPDATE incidents SET status = 'investigating', current_run_id = ?,
          version = version + 1, timeline_sequence = timeline_sequence + 1,
          updated_at = ?
          WHERE tenant_id = ? AND id = ? AND status = 'received'
          RETURNING timeline_sequence`,
        args: [input.eventId, now, input.tenantId, input.incidentId],
      });
      const row = updated.rows[0];
      if (!row) throw new DomainError("CONFLICT");
      await insertTimelineAndOutbox(tx, {
        timelineId: ids.next(),
        eventId: ids.next(),
        incidentId: input.incidentId,
        tenantId: input.tenantId,
        sequence: Number(row.timeline_sequence),
        type: "workflow.investigation_started",
        eventType: "security.workflow.updated",
        runId: input.eventId,
        correlationId: input.correlationId,
        causationId: input.eventId,
        occurredAt: now,
        payload: { alertId: input.alertId, status: "investigating" },
      });
      return { duplicate: false, runId: input.eventId };
    });
  } catch (error) {
    const existing = await store.execute({
      sql: `SELECT incident_id, tenant_id, workflow_id FROM workflow_runs
        WHERE run_id = ?`,
      args: [input.eventId],
    });
    if (existing.rows[0]) {
      assertEquivalentMarker(existing.rows[0], input);
      return { duplicate: true, runId: input.eventId };
    }
    throw error;
  }
}

export async function hasWorkflowRun(
  store: OperationalStore,
  runId: string,
): Promise<boolean> {
  const result = await store.execute({
    sql: "SELECT 1 FROM workflow_runs WHERE run_id = ?",
    args: [runId],
  });
  return result.rows.length > 0;
}

function assertEquivalentMarker(
  row: Record<string, unknown>,
  input: StartInvestigationInput,
): void {
  if (
    row.incident_id !== input.incidentId ||
    row.tenant_id !== input.tenantId ||
    row.workflow_id !== INCIDENT_INGESTION_WORKFLOW_ID
  ) {
    throw new DomainError("CONFLICT");
  }
}
