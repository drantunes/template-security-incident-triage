import { createStep, createWorkflow } from "@mastra/core/workflows";
import type { ToolObserve } from "@mastra/core/tools";
import { z } from "zod";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import {
  INCIDENT_INGESTION_WORKFLOW_ID,
  materializeInvestigationStart,
} from "../../db/workflow-run-operations.js";
import { opaqueId, tenantIdSchema } from "../../schemas/common.js";
import { CorrelationSchema } from "../../evidence/contracts.js";
import {
  createRetrieveRunbookStep,
  InvestigationStartedSchema,
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
import { readPhase4Config, readPhase6Config } from "../../env.js";
import type { InvestigatorInvoker } from "../agents/investigator-output.js";
import type { SupervisorInvoker } from "../agents/soc-supervisor.js";
import type { CorrelationAnalystInvoker } from "../agents/correlation-analyst.js";
import type { EvidenceReadTool } from "../tools/evidence-read-tool.js";
import {
  createClassifySeverityStep,
  type Phase5StepDependencies,
} from "../steps/classify-severity.js";
import { createGenerateSummaryStep } from "../steps/generate-summary.js";
import { createProposeContainmentStep } from "../steps/propose-containment.js";
import { createValidateContainmentStep } from "../steps/validate-containment.js";
import { Phase5ResultSchema } from "../../triage/decision-contracts.js";
import { Phase6ResultSchema } from "../../approval/phase6-contracts.js";
import { createRequestApprovalStep } from "../steps/request-approval.js";
import { createOpenExternalIncidentStep } from "../steps/open-external-incident.js";
import { createAwaitApprovalStep } from "../steps/await-approval.js";
import { createExecuteContainmentStep } from "../steps/execute-containment.js";
import { createVerifyContainmentStep } from "../steps/verify-containment.js";
import { createUpdateExternalIncidentStep } from "../steps/update-external-incident.js";
import { createFinalizeIncidentStep } from "../steps/finalize-incident.js";
import type { IncidentProvider } from "../../providers/incident-provider.js";
import { MockIncidentProvider } from "../../providers/mock-incident-provider.js";
import type { MockContainmentState } from "../../containment/mock-state.js";
import type { IdentityProvider } from "../../providers/identity-provider.js";

export const IncidentIngestionInputSchema = z
  .object({
    eventId: opaqueId,
    incidentId: opaqueId,
    tenantId: tenantIdSchema,
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
  phase5Dependencies: Phase5StepDependencies = {},
  phase6Dependencies: Readonly<{
    enabled?: boolean;
    provider?: IncidentProvider;
    state?: MockContainmentState;
    mode?: "mock" | "staging" | "production";
    timeoutMs?: number;
    rateLimit?: number;
    identityProvider?: IdentityProvider;
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
        const result = await materializeInvestigationStart(store, inputData, {
          ...(evidenceDependencies.clock
            ? { clock: evidenceDependencies.clock }
            : {}),
          ...(evidenceDependencies.ids
            ? { ids: evidenceDependencies.ids }
            : {}),
        });
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
  const phase5 = {
    ...phase5Dependencies,
    openStore: phase5Dependencies.openStore ?? openStore,
  };
  const phase6Config = readPhase6Config();
  const phase6Provider =
    phase6Dependencies.provider ?? new MockIncidentProvider({ openStore });
  const phase6State: MockContainmentState = phase6Dependencies.state ?? {
    sessions: new Map(),
    roles: new Map(),
    devices: new Map(),
    reauthentication: new Map(),
    calls: new Map(),
  };
  const phase6Shared = {
    openStore,
    ...(phase6Dependencies.clock
      ? { clock: phase6Dependencies.clock }
      : evidenceDependencies.clock
        ? { clock: evidenceDependencies.clock }
        : {}),
    ...(phase6Dependencies.ids
      ? { ids: phase6Dependencies.ids }
      : evidenceDependencies.ids
        ? { ids: evidenceDependencies.ids }
        : {}),
  };
  const phase6Enabled = phase6Dependencies.enabled === true;
  const workflow = createWorkflow({
    id: INCIDENT_INGESTION_WORKFLOW_ID,
    description:
      "Triages an incident, persists approval, suspends for a manager decision, and executes only approved mock containment.",
    inputSchema: IncidentIngestionInputSchema,
    outputSchema: phase6Enabled ? Phase6ResultSchema : Phase5ResultSchema,
  })
    .then(startInvestigation)
    .then(loadContext)
    .then(validateSupervisor)
    .parallel([gatherIdentity, gatherEndpoint, gatherCloud])
    .then(correlate)
    .then(prepareRunbookRetrieval)
    .then(createRetrieveRunbookStep({ openStore, ...retrieveDependencies }))
    .then(createClassifySeverityStep(phase5))
    .then(createGenerateSummaryStep(phase5))
    .then(createProposeContainmentStep(phase5))
    .then(createValidateContainmentStep(phase5));
  if (!phase6Enabled) return workflow.commit();
  return workflow
    .then(createRequestApprovalStep(phase6Shared))
    .then(
      createOpenExternalIncidentStep({
        ...phase6Shared,
        provider: phase6Provider,
      }),
    )
    .then(createAwaitApprovalStep(phase6Shared))
    .then(
      createExecuteContainmentStep({
        ...phase6Shared,
        state: phase6State,
        mode: phase6Dependencies.mode ?? phase6Config.mode,
        timeoutMs: phase6Dependencies.timeoutMs ?? phase6Config.actionTimeoutMs,
        rateLimit: phase6Dependencies.rateLimit ?? phase6Config.rateLimit,
        ...(phase6Dependencies.identityProvider
          ? { identityProvider: phase6Dependencies.identityProvider }
          : {}),
      }),
    )
    .then(createVerifyContainmentStep(phase6Shared))
    .then(
      createUpdateExternalIncidentStep({
        ...phase6Shared,
        provider: phase6Provider,
      }),
    )
    .then(createFinalizeIncidentStep(phase6Shared))
    .commit();
}

const phase4Config = readPhase4Config();
export const incidentIngestionWorkflow = createIncidentIngestionWorkflow(
  createLibSqlOperationalStore,
  {},
  { timeouts: phase4Config.timeouts },
  {},
  { enabled: true },
);
