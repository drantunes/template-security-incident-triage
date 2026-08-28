import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import {
  INCIDENT_INGESTION_WORKFLOW_ID,
  materializeInvestigationStart,
} from "../../db/workflow-run-operations.js";
import { opaqueId } from "../../schemas/common.js";
import {
  createRetrieveRunbookStep,
  InvestigationStartedSchema,
  RunbookRetrievedSchema,
  type RetrieveStepDependencies,
} from "../steps/retrieve-runbook.js";

export const IncidentIngestionInputSchema = z
  .object({
    eventId: opaqueId,
    incidentId: opaqueId,
    tenantId: opaqueId,
    alertId: opaqueId,
    correlationId: opaqueId,
  })
  .strict();

export function createIncidentIngestionWorkflow(
  openStore: () => OperationalStore = createLibSqlOperationalStore,
  retrieveDependencies: RetrieveStepDependencies = {},
) {
  const startInvestigation = createStep({
    id: "start-investigation",
    description:
      "Materializes the idempotent received-to-investigating marker.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema: InvestigationStartedSchema,
    execute: async ({ inputData }) => {
      const store = openStore();
      try {
        const result = await materializeInvestigationStart(store, inputData);
        return { ...inputData, ...result };
      } finally {
        store.close();
      }
    },
  });
  return createWorkflow({
    id: INCIDENT_INGESTION_WORKFLOW_ID,
    description:
      "Starts investigation and retrieves the eligible Phase 3 runbook.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema: RunbookRetrievedSchema,
  })
    .then(startInvestigation)
    .then(createRetrieveRunbookStep({ openStore, ...retrieveDependencies }))
    .commit();
}

export const incidentIngestionWorkflow = createIncidentIngestionWorkflow();
