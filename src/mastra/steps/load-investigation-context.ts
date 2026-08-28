import { createStep } from "@mastra/core/workflows";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import { DomainError, parseDomainSchema } from "../../domain/errors.js";
import {
  InvestigationContextSchema,
  type InvestigationContext,
} from "../../evidence/contracts.js";
import { AlertSchema } from "../../schemas/alert.js";
import { InvestigationStartedSchema } from "./retrieve-runbook.js";

export async function loadInvestigationContext(
  store: OperationalStore,
  input: typeof InvestigationStartedSchema._output,
): Promise<InvestigationContext> {
  const result = await store.execute({
    sql: `SELECT i.kind, i.subject_id, i.current_run_id, a.canonical_json
      FROM incidents i
      JOIN alerts a ON a.tenant_id = i.tenant_id AND a.incident_id = i.id
      WHERE i.tenant_id = ? AND i.id = ? AND a.id = ?`,
    args: [input.tenantId, input.incidentId, input.alertId],
  });
  const row = result.rows[0];
  if (!row) throw new DomainError("NOT_FOUND");
  if (row.current_run_id !== input.eventId) throw new DomainError("CONFLICT");
  let canonical: unknown;
  try {
    canonical = JSON.parse(String(row.canonical_json));
  } catch {
    throw new DomainError("VALIDATION_FAILED");
  }
  const alert = parseDomainSchema(AlertSchema, canonical);
  if (
    alert.tenantId !== input.tenantId ||
    alert.alertId !== input.alertId ||
    alert.subjectId !== row.subject_id ||
    alert.kind !== row.kind
  ) {
    throw new DomainError("CONFLICT");
  }
  return parseDomainSchema(InvestigationContextSchema, {
    schemaVersion: 1,
    eventId: input.eventId,
    alertId: input.alertId,
    incidentId: input.incidentId,
    tenantId: input.tenantId,
    correlationId: input.correlationId,
    subjectId: alert.subjectId,
    workflowRunId: input.eventId,
    incidentKind: alert.kind,
    occurredAt: alert.occurredAt,
    ...(alert.sessionId ? { sessionId: alert.sessionId } : {}),
    ...(alert.deviceId ? { deviceId: alert.deviceId } : {}),
    ...(alert.ip ? { ip: alert.ip } : {}),
  });
}

export function createLoadInvestigationContextStep(
  openStore: () => OperationalStore = createLibSqlOperationalStore,
) {
  return createStep({
    id: "load-investigation-context",
    description:
      "Loads and validates tenant-scoped alert, incident, subject, and run context.",
    inputSchema: InvestigationStartedSchema,
    outputSchema: InvestigationContextSchema,
    execute: async ({ inputData }) => {
      const store = openStore();
      try {
        return await loadInvestigationContext(store, inputData);
      } finally {
        store.close();
      }
    },
  });
}
