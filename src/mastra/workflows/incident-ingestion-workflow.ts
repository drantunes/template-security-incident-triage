import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import {
  INCIDENT_INGESTION_WORKFLOW_ID,
  materializeInvestigationStart,
} from "../../db/workflow-run-operations.js";
import { opaqueId } from "../../schemas/common.js";

export const IncidentIngestionInputSchema = z
  .object({
    eventId: opaqueId,
    incidentId: opaqueId,
    tenantId: opaqueId,
    alertId: opaqueId,
    correlationId: opaqueId,
  })
  .strict();

const outputSchema = z
  .object({
    runId: opaqueId,
    duplicate: z.boolean(),
  })
  .strict();

export function createIncidentIngestionWorkflow(
  openStore: () => OperationalStore = createLibSqlOperationalStore,
) {
  const startInvestigation = createStep({
    id: "start-investigation",
    description:
      "Materializes the idempotent received-to-investigating marker.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema,
    execute: async ({ inputData }) => {
      const store = openStore();
      try {
        return await materializeInvestigationStart(store, inputData);
      } finally {
        store.close();
      }
    },
  });
  return createWorkflow({
    id: INCIDENT_INGESTION_WORKFLOW_ID,
    description: "Starts only the Phase 2 investigation state transition.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema,
  })
    .then(startInvestigation)
    .commit();
}

export const incidentIngestionWorkflow = createIncidentIngestionWorkflow();
