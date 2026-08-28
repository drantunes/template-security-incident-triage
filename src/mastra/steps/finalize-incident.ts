import { createStep } from "@mastra/core/workflows";

import {
  ContainmentExecutionResultSchema,
  Phase6ResultSchema,
} from "../../approval/phase6-contracts.js";
import { transitionIncident } from "../../db/incident-operations.js";
import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import type { Clock } from "../../domain/clock.js";
import type { IdGenerator } from "../../domain/id-generator.js";
import { DomainError } from "../../domain/errors.js";
import type { ContainmentExecutionResult } from "../../approval/phase6-contracts.js";
import {
  canonicalizePlanValue,
  verifyPlanHash,
} from "../../containment/plan-canonicalization.js";
import { ContainmentPlanSchema } from "../../schemas/containment.js";

export function createFinalizeIncidentStep(
  dependencies: Readonly<{
    openStore?: () => OperationalStore;
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
) {
  return createStep({
    id: "finalize-incident",
    description:
      "Closes rejected or fully contained incidents and preserves failed/partial state.",
    inputSchema: ContainmentExecutionResultSchema,
    outputSchema: Phase6ResultSchema,
    execute: async ({ inputData }) => {
      if (
        inputData.status === "manual-review" ||
        inputData.status === "blocked"
      )
        return inputData;
      if (inputData.status === "containment-failed") {
        return {
          status: "failed" as const,
          incidentId: inputData.plan.incidentId,
          approvalId: inputData.authoritative.approvalId,
          partial: inputData.partial,
          outcomes: inputData.outcomes,
        };
      }
      if (inputData.status === "expired") {
        return {
          status: "expired" as const,
          incidentId: inputData.plan.incidentId,
          approvalId: inputData.authoritative.approvalId,
        };
      }
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        const readiness = await assertTerminalReadiness(store, inputData);
        if (readiness.incidentStatus === "closed") {
          assertClosedEvidence(readiness, inputData);
          return finalResult(inputData);
        }
        await transitionIncident(
          store,
          {
            tenantId: inputData.plan.tenantId,
            incidentId: inputData.plan.incidentId,
            expectedVersion: readiness.incidentVersion,
            to: "closed",
            runId: inputData.workflowRunId,
            correlationId: inputData.correlationId,
            causationId: inputData.authoritative.approvalId,
          },
          {
            ...(dependencies.clock ? { clock: dependencies.clock } : {}),
            ...(dependencies.ids ? { ids: dependencies.ids } : {}),
            assertReady: async (tx) => {
              const guarded = await assertTerminalReadiness(tx, inputData);
              if (
                guarded.incidentStatus === "closed" ||
                guarded.incidentVersion !== readiness.incidentVersion
              ) {
                throw new DomainError("CONFLICT");
              }
            },
          },
        );
        return finalResult(inputData);
      } finally {
        store.close();
      }
    },
  });
}

type FinalizableInput = Extract<
  ContainmentExecutionResult,
  { status: "rejected" | "containment-succeeded" }
>;

function finalResult(input: FinalizableInput) {
  return input.status === "rejected"
    ? {
        status: "rejected" as const,
        incidentId: input.plan.incidentId,
        approvalId: input.authoritative.approvalId,
      }
    : {
        status: "contained" as const,
        incidentId: input.plan.incidentId,
        approvalId: input.authoritative.approvalId,
        outcomes: input.outcomes,
      };
}

type TerminalReadiness = Readonly<{
  incidentStatus: "contained" | "rejected" | "closed";
  incidentVersion: number;
  closedAt: string | null;
  terminalOccurredAt: string | null;
  terminalCorrelationId: string | null;
  terminalFrom: string | null;
}>;

async function assertTerminalReadiness(
  store: Pick<OperationalStore, "execute">,
  input: FinalizableInput,
): Promise<TerminalReadiness> {
  const binding = await store.execute({
    sql: `SELECT incident.status AS incident_status,
        incident.version AS incident_version, incident.current_run_id,
        incident.current_plan_id, incident.closed_at,
        approval.id AS approval_id, approval.tenant_id, approval.incident_id,
        approval.plan_id, approval.decision, approval.workflow_run_id,
        approval.plan_hash_version, approval.plan_hash, approval.decided_by,
        approval.decided_by_role, approval.decided_at, approval.expires_at,
        plan.expires_at AS plan_expires_at, plan.plan_json,
        (SELECT requested.correlation_id FROM timeline_events requested
          WHERE requested.tenant_id = incident.tenant_id
            AND requested.incident_id = incident.id
            AND requested.type = 'approval.requested'
            AND json_extract(requested.payload_json, '$.approvalId') = approval.id
            AND json_extract(requested.payload_json, '$.planId') = approval.plan_id
          ORDER BY requested.sequence DESC LIMIT 1) AS request_correlation_id,
        (SELECT decided.occurred_at FROM timeline_events decided
          WHERE decided.tenant_id = incident.tenant_id
            AND decided.incident_id = incident.id
            AND decided.type = 'approval.decided'
            AND decided.causation_id = approval.id
            AND json_extract(decided.payload_json, '$.decision') = approval.decision
          ORDER BY decided.sequence DESC LIMIT 1) AS decision_occurred_at,
        (SELECT completed.occurred_at FROM timeline_events completed
          WHERE completed.tenant_id = incident.tenant_id
            AND completed.incident_id = incident.id
            AND completed.type = 'containment.completed'
            AND completed.causation_id = approval.id
            AND json_extract(completed.payload_json, '$.status') = 'contained'
          ORDER BY completed.sequence DESC LIMIT 1) AS containment_occurred_at,
        (SELECT completed.correlation_id FROM timeline_events completed
          WHERE completed.tenant_id = incident.tenant_id
            AND completed.incident_id = incident.id
            AND completed.type = 'containment.completed'
            AND completed.causation_id = approval.id
            AND json_extract(completed.payload_json, '$.status') = 'contained'
          ORDER BY completed.sequence DESC LIMIT 1) AS containment_correlation_id,
        (SELECT terminal.occurred_at FROM timeline_events terminal
          WHERE terminal.tenant_id = incident.tenant_id
            AND terminal.incident_id = incident.id
            AND terminal.type = 'incident.status_changed'
            AND terminal.causation_id = approval.id
            AND json_extract(terminal.payload_json, '$.to') = 'closed'
          ORDER BY terminal.sequence DESC LIMIT 1) AS terminal_occurred_at,
        (SELECT terminal.correlation_id FROM timeline_events terminal
          WHERE terminal.tenant_id = incident.tenant_id
            AND terminal.incident_id = incident.id
            AND terminal.type = 'incident.status_changed'
            AND terminal.causation_id = approval.id
            AND json_extract(terminal.payload_json, '$.to') = 'closed'
          ORDER BY terminal.sequence DESC LIMIT 1) AS terminal_correlation_id,
        (SELECT json_extract(terminal.payload_json, '$.from')
          FROM timeline_events terminal
          WHERE terminal.tenant_id = incident.tenant_id
            AND terminal.incident_id = incident.id
            AND terminal.type = 'incident.status_changed'
            AND terminal.causation_id = approval.id
            AND json_extract(terminal.payload_json, '$.to') = 'closed'
          ORDER BY terminal.sequence DESC LIMIT 1) AS terminal_from
      FROM incidents incident
      JOIN approvals approval
        ON approval.tenant_id = incident.tenant_id
        AND approval.incident_id = incident.id
      JOIN containment_plans plan
        ON plan.tenant_id = approval.tenant_id
        AND plan.incident_id = approval.incident_id
        AND plan.id = approval.plan_id
      WHERE incident.tenant_id = ? AND incident.id = ?
        AND approval.id = ? AND approval.plan_id = ?`,
    args: [
      input.plan.tenantId,
      input.plan.incidentId,
      input.authoritative.approvalId,
      input.plan.planId,
    ],
  });
  const row = binding.rows[0];
  let persistedPlan: ReturnType<typeof ContainmentPlanSchema.parse> | undefined;
  if (typeof row?.plan_json === "string") {
    try {
      persistedPlan = ContainmentPlanSchema.parse(JSON.parse(row.plan_json));
    } catch {
      persistedPlan = undefined;
    }
  }
  const expectedDecision =
    input.status === "rejected" ? "rejected" : "approved";
  const expectedPreCloseStatus =
    input.status === "rejected" ? "rejected" : "contained";
  const incidentVersion = Number(row?.incident_version);
  const incidentStatus = row?.incident_status;
  const isClosed = incidentStatus === "closed";
  if (
    !row ||
    (incidentStatus !== expectedPreCloseStatus && !isClosed) ||
    !Number.isSafeInteger(incidentVersion) ||
    incidentVersion < 0 ||
    !persistedPlan ||
    !verifyPlanHash(input.plan) ||
    !verifyPlanHash(persistedPlan) ||
    canonicalizePlanValue(persistedPlan) !==
      canonicalizePlanValue(input.plan) ||
    row.current_run_id !== input.workflowRunId ||
    row.current_plan_id !== input.plan.planId ||
    (isClosed
      ? typeof row.closed_at !== "string"
      : row.closed_at !== null ||
        row.terminal_occurred_at !== null ||
        row.terminal_correlation_id !== null ||
        row.terminal_from !== null) ||
    row.approval_id !== input.authoritative.approvalId ||
    row.tenant_id !== input.authoritative.tenantId ||
    row.incident_id !== input.authoritative.incidentId ||
    row.plan_id !== input.authoritative.planId ||
    row.workflow_run_id !== input.workflowRunId ||
    row.workflow_run_id !== input.authoritative.workflowRunId ||
    row.decision !== expectedDecision ||
    row.decision !== input.authoritative.decision ||
    Number(row.plan_hash_version) !== input.plan.planHashVersion ||
    Number(row.plan_hash_version) !== input.authoritative.planHashVersion ||
    row.plan_hash !== input.plan.planHash ||
    row.plan_hash !== input.authoritative.planHash ||
    row.decided_by !== input.authoritative.decidedBy ||
    row.decided_by_role !== input.authoritative.decidedByRole ||
    row.decided_at !== input.authoritative.decidedAt ||
    row.request_correlation_id !== input.correlationId ||
    row.decision_occurred_at !== row.decided_at ||
    (input.status === "rejected"
      ? row.containment_occurred_at !== null ||
        row.containment_correlation_id !== null
      : typeof row.containment_occurred_at !== "string" ||
        row.containment_correlation_id !== input.correlationId) ||
    row.expires_at !== input.authoritative.expiresAt ||
    row.plan_expires_at !== input.plan.expiresAt ||
    input.authoritative.tenantId !== input.plan.tenantId ||
    input.authoritative.incidentId !== input.plan.incidentId ||
    input.authoritative.planId !== input.plan.planId ||
    input.authoritative.workflowRunId !== input.workflowRunId ||
    input.authoritative.planHashVersion !== input.plan.planHashVersion ||
    input.authoritative.planHash !== input.plan.planHash ||
    input.authoritative.expiresAt !== input.plan.expiresAt
  ) {
    throw new DomainError("CONFLICT");
  }
  if (input.status === "rejected") {
    const attempts = await store.execute({
      sql: `SELECT count(*) AS count FROM containment_action_attempts
        WHERE tenant_id = ? AND incident_id = ? AND plan_id = ?`,
      args: [input.plan.tenantId, input.plan.incidentId, input.plan.planId],
    });
    if (Number(attempts.rows[0]?.count) !== 0) {
      throw new DomainError("CONFLICT");
    }
    return terminalReadiness(row, incidentStatus, incidentVersion);
  }
  const actions = await store.execute({
    sql: `SELECT action.action_id, action.ordinal, action.status,
        attempt.verification, attempt.provider_ref
      FROM containment_actions action
      LEFT JOIN containment_action_attempts attempt
        ON attempt.tenant_id = action.tenant_id
        AND attempt.plan_id = action.plan_id
        AND attempt.action_id = action.action_id
        AND attempt.attempt = (
          SELECT max(latest.attempt) FROM containment_action_attempts latest
          WHERE latest.tenant_id = action.tenant_id
            AND latest.plan_id = action.plan_id
            AND latest.action_id = action.action_id
        )
      WHERE action.tenant_id = ? AND action.incident_id = ? AND action.plan_id = ?
      ORDER BY action.ordinal`,
    args: [input.plan.tenantId, input.plan.incidentId, input.plan.planId],
  });
  if (actions.rows.length !== input.outcomes.length) {
    throw new DomainError("CONFLICT");
  }
  const persisted = new Map(
    actions.rows.map((action) => [String(action.action_id), action]),
  );
  const outcomeIds = new Set(input.outcomes.map((outcome) => outcome.actionId));
  if (
    outcomeIds.size !== input.outcomes.length ||
    outcomeIds.size !== persisted.size
  ) {
    throw new DomainError("CONFLICT");
  }
  for (const [index, outcome] of input.outcomes.entries()) {
    const orderedAction = actions.rows[index];
    const action = persisted.get(outcome.actionId);
    if (
      !action ||
      orderedAction?.action_id !== outcome.actionId ||
      outcome.status !== "completed" ||
      outcome.verification !== "verified" ||
      action.status !== "completed" ||
      action.verification !== "verified" ||
      action.provider_ref !== outcome.providerRef
    ) {
      throw new DomainError("CONFLICT");
    }
  }
  return terminalReadiness(row, incidentStatus, incidentVersion);
}

function terminalReadiness(
  row: Record<string, unknown>,
  incidentStatus: unknown,
  incidentVersion: number,
): TerminalReadiness {
  return {
    incidentStatus: incidentStatus as TerminalReadiness["incidentStatus"],
    incidentVersion,
    closedAt: typeof row.closed_at === "string" ? row.closed_at : null,
    terminalOccurredAt:
      typeof row.terminal_occurred_at === "string"
        ? row.terminal_occurred_at
        : null,
    terminalCorrelationId:
      typeof row.terminal_correlation_id === "string"
        ? row.terminal_correlation_id
        : null,
    terminalFrom:
      typeof row.terminal_from === "string" ? row.terminal_from : null,
  };
}

function assertClosedEvidence(
  readiness: TerminalReadiness,
  input: FinalizableInput,
): void {
  const expectedFrom = input.status === "rejected" ? "rejected" : "contained";
  if (
    readiness.closedAt !== readiness.terminalOccurredAt ||
    readiness.terminalCorrelationId !== input.correlationId ||
    readiness.terminalFrom !== expectedFrom
  ) {
    throw new DomainError("CONFLICT");
  }
}
