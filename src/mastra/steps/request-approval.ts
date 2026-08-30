import { createHash } from "node:crypto";
import { createStep } from "@mastra/core/workflows";

import { requestApproval } from "../../db/approval-operations.js";
import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import type { Clock } from "../../domain/clock.js";
import { systemClock } from "../../domain/clock.js";
import type { IdGenerator } from "../../domain/id-generator.js";
import { ApprovalRequestSchema } from "../../schemas/approval.js";
import { ApprovalRequestedResultSchema } from "../../approval/phase6-contracts.js";
import { Phase5ResultSchema } from "../../triage/decision-contracts.js";
import { withinWorkflowPhase10Boundary } from "../phase10-trace-context.js";

export function createRequestApprovalStep(
  dependencies: Readonly<{
    openStore?: () => OperationalStore;
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
) {
  return createStep({
    id: "request-approval",
    description:
      "Atomically persists the validated plan, approval, transition, timeline, and outbox.",
    inputSchema: Phase5ResultSchema,
    outputSchema: ApprovalRequestedResultSchema,
    execute: async ({ inputData, getInitData }) => {
      if (inputData.status !== "ready-for-approval") return inputData;
      const init = getInitData<{
        eventId: string;
        incidentId: string;
        tenantId: string;
        correlationId: string;
      }>();
      if (
        inputData.plan.incidentId !== init.incidentId ||
        inputData.plan.tenantId !== init.tenantId ||
        inputData.decision.workflowRunId !== init.eventId ||
        inputData.decision.incidentId !== init.incidentId ||
        inputData.decision.tenantId !== init.tenantId
      ) {
        return {
          status: "blocked" as const,
          incidentId: init.incidentId,
          reasonCodes: ["SCOPE_CHECK_FAILED" as const],
        };
      }
      const clock = dependencies.clock ?? systemClock;
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      let requestedAt = clock.now();
      try {
        const prior = await store.execute({
          sql: `SELECT requested_at FROM approvals
            WHERE tenant_id = ? AND incident_id = ? AND plan_id = ?`,
          args: [init.tenantId, init.incidentId, inputData.plan.planId],
        });
        if (prior.rows[0]?.requested_at) {
          requestedAt = String(prior.rows[0].requested_at);
        }
        const approval = ApprovalRequestSchema.parse({
          schemaVersion: 1,
          approvalId: `approval_${createHash("sha256")
            .update(
              `${init.tenantId}\0${init.incidentId}\0${init.eventId}\0${inputData.plan.planHash}`,
            )
            .digest("hex")}`,
          planId: inputData.plan.planId,
          incidentId: init.incidentId,
          tenantId: init.tenantId,
          planHashVersion: inputData.plan.planHashVersion,
          planHash: inputData.plan.planHash,
          requestedAt,
          expiresAt: inputData.plan.expiresAt,
          status: "pending",
        });
        const incident = await store.execute({
          sql: `SELECT version FROM incidents WHERE tenant_id = ? AND id = ?
            AND current_run_id = ? AND status IN ('investigating','awaiting_approval')`,
          args: [init.tenantId, init.incidentId, init.eventId],
        });
        if (!incident.rows[0]) {
          return {
            status: "blocked" as const,
            incidentId: init.incidentId,
            reasonCodes: ["SCOPE_CHECK_FAILED" as const],
          };
        }
        const expectedIncidentVersion = Number(incident.rows[0].version);
        await withinWorkflowPhase10Boundary(
          store,
          {
            tenantId: init.tenantId,
            incidentId: init.incidentId,
            workflowRunId: init.eventId,
            correlationId: init.correlationId,
            boundary: "approval.request",
            stepId: "request-approval",
          },
          () =>
            requestApproval(
              store,
              {
                plan: inputData.plan,
                approval,
                expectedIncidentVersion,
                runId: init.eventId,
                correlationId: init.correlationId,
              },
              {
                clock,
                ...(dependencies.ids ? { ids: dependencies.ids } : {}),
              },
            ),
        );
        return ApprovalRequestedResultSchema.parse({
          status: "approval-requested",
          decision: inputData.decision,
          summary: inputData.summary,
          plan: inputData.plan,
          approval,
          workflowRunId: init.eventId,
          correlationId: init.correlationId,
        });
      } finally {
        store.close();
      }
    },
  });
}
