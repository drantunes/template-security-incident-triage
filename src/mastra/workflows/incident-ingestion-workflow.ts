import { createStep, createWorkflow } from "@mastra/core/workflows";
import type { ToolObserve } from "@mastra/core/tools";
import { z } from "zod";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import {
  INCIDENT_INGESTION_WORKFLOW_ID,
  materializeInvestigationStart,
} from "../../db/workflow-run-operations.js";
import { opaqueId } from "../../schemas/common.js";
import { CorrelationSchema } from "../../evidence/contracts.js";
import {
  createRetrieveRunbookStep,
  InvestigationStartedSchema,
  RunbookRetrievedSchema,
  type RetrieveStepDependencies,
} from "../steps/retrieve-runbook.js";
import { createLoadInvestigationContextStep } from "../steps/load-investigation-context.js";
import { createValidateSupervisorScopeStep } from "../steps/validate-supervisor-scope.js";
import { createGatherIdentityEvidenceStep } from "../steps/gather-identity-evidence.js";
import { createGatherEndpointEvidenceStep } from "../steps/gather-endpoint-evidence.js";
import { createGatherCloudEvidenceStep } from "../steps/gather-cloud-evidence.js";
import { createCorrelateEventsStep } from "../steps/correlate-events.js";
import type {
  CloudEvidenceProvider,
  EndpointEvidenceProvider,
  IdentityEvidenceProvider,
} from "../../providers/evidence-provider.js";
import type { Clock } from "../../domain/clock.js";
import type { IdGenerator } from "../../domain/id-generator.js";
import { readPhase4Config } from "../../env.js";
import type { InvestigatorInvoker } from "../agents/investigator-output.js";
import type { SupervisorInvoker } from "../agents/soc-supervisor.js";
import type { CorrelationAnalystInvoker } from "../agents/correlation-analyst.js";
import type { EvidenceReadTool } from "../tools/evidence-read-tool.js";

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
  evidenceDependencies: Readonly<{
    identityProvider?: IdentityEvidenceProvider;
    endpointProvider?: EndpointEvidenceProvider;
    cloudProvider?: CloudEvidenceProvider;
    identityTool?: EvidenceReadTool;
    endpointTool?: EvidenceReadTool;
    cloudTool?: EvidenceReadTool;
    toolObserve?: ToolObserve;
    identityInvestigator?: InvestigatorInvoker;
    endpointInvestigator?: InvestigatorInvoker;
    cloudInvestigator?: InvestigatorInvoker;
    supervisor?: SupervisorInvoker;
    correlationAnalyst?: CorrelationAnalystInvoker;
    timeoutMs?: number;
    timeouts?: Partial<Record<"identity" | "endpoint" | "cloud", number>>;
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
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
  const loadContext = createLoadInvestigationContextStep(openStore);
  const validateSupervisor = createValidateSupervisorScopeStep(
    evidenceDependencies.supervisor,
  );
  const shared = {
    openStore,
    ...(evidenceDependencies.timeoutMs === undefined
      ? {}
      : { timeoutMs: evidenceDependencies.timeoutMs }),
    ...(evidenceDependencies.clock
      ? { clock: evidenceDependencies.clock }
      : {}),
    ...(evidenceDependencies.ids ? { ids: evidenceDependencies.ids } : {}),
    ...(evidenceDependencies.toolObserve
      ? { toolObserve: evidenceDependencies.toolObserve }
      : {}),
  };
  const gatherIdentity = createGatherIdentityEvidenceStep({
    ...shared,
    ...(evidenceDependencies.timeouts?.identity === undefined
      ? {}
      : { timeoutMs: evidenceDependencies.timeouts.identity }),
    ...(evidenceDependencies.identityProvider
      ? { provider: evidenceDependencies.identityProvider }
      : {}),
    ...(evidenceDependencies.identityTool
      ? { tool: evidenceDependencies.identityTool }
      : {}),
    ...(evidenceDependencies.identityInvestigator
      ? { investigator: evidenceDependencies.identityInvestigator }
      : {}),
  });
  const gatherEndpoint = createGatherEndpointEvidenceStep({
    ...shared,
    ...(evidenceDependencies.timeouts?.endpoint === undefined
      ? {}
      : { timeoutMs: evidenceDependencies.timeouts.endpoint }),
    ...(evidenceDependencies.endpointProvider
      ? { provider: evidenceDependencies.endpointProvider }
      : {}),
    ...(evidenceDependencies.endpointTool
      ? { tool: evidenceDependencies.endpointTool }
      : {}),
    ...(evidenceDependencies.endpointInvestigator
      ? { investigator: evidenceDependencies.endpointInvestigator }
      : {}),
  });
  const gatherCloud = createGatherCloudEvidenceStep({
    ...shared,
    ...(evidenceDependencies.timeouts?.cloud === undefined
      ? {}
      : { timeoutMs: evidenceDependencies.timeouts.cloud }),
    ...(evidenceDependencies.cloudProvider
      ? { provider: evidenceDependencies.cloudProvider }
      : {}),
    ...(evidenceDependencies.cloudTool
      ? { tool: evidenceDependencies.cloudTool }
      : {}),
    ...(evidenceDependencies.cloudInvestigator
      ? { investigator: evidenceDependencies.cloudInvestigator }
      : {}),
  });
  const correlate = createCorrelateEventsStep({
    openStore,
    ...(evidenceDependencies.clock
      ? { clock: evidenceDependencies.clock }
      : {}),
    ...(evidenceDependencies.correlationAnalyst
      ? { analyst: evidenceDependencies.correlationAnalyst }
      : {}),
  });
  const prepareRunbookRetrieval = createStep({
    id: "prepare-runbook-retrieval",
    inputSchema: CorrelationSchema,
    outputSchema: InvestigationStartedSchema,
    execute: async ({ inputData, getStepResult }) => ({
      eventId: inputData.context.eventId,
      incidentId: inputData.context.incidentId,
      tenantId: inputData.context.tenantId,
      alertId: inputData.context.alertId,
      correlationId: inputData.context.correlationId,
      runId: inputData.context.workflowRunId,
      duplicate: getStepResult(startInvestigation).duplicate,
    }),
  });
  return createWorkflow({
    id: INCIDENT_INGESTION_WORKFLOW_ID,
    description:
      "Starts investigation, gathers and correlates evidence in parallel, then retrieves the runbook.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema: RunbookRetrievedSchema,
  })
    .then(startInvestigation)
    .then(loadContext)
    .then(validateSupervisor)
    .parallel([gatherIdentity, gatherEndpoint, gatherCloud])
    .then(correlate)
    .then(prepareRunbookRetrieval)
    .then(createRetrieveRunbookStep({ openStore, ...retrieveDependencies }))
    .commit();
}

const phase4Config = readPhase4Config();
export const incidentIngestionWorkflow = createIncidentIngestionWorkflow(
  createLibSqlOperationalStore,
  {},
  { timeouts: phase4Config.timeouts },
);
