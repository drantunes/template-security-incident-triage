import { createStep } from "@mastra/core/workflows";

import {
  ApprovalRequestedResultSchema,
  ApprovalResolvedResultSchema,
} from "../../approval/phase6-contracts.js";
import { readConsumedResumeReceipt } from "../../db/approval-operations.js";
import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import type { Clock } from "../../domain/clock.js";
import {
  ApprovalResumePayloadSchema,
  ApprovalSuspendPayloadSchema,
} from "../../schemas/approval.js";
import { startPhase10Boundary } from "../observability.js";
import {
  advanceWorkflowPhase10Trace,
  readWorkflowPhase10Trace,
} from "../phase10-trace-context.js";

export function createAwaitApprovalStep(
  dependencies: Readonly<{
    openStore?: () => OperationalStore;
    clock?: Clock;
  }> = {},
) {
  return createStep({
    id: "await-approval",
    description:
      "Suspends with a minimal public payload and resumes only by consuming a bound one-shot token.",
    inputSchema: ApprovalRequestedResultSchema,
    outputSchema: ApprovalResolvedResultSchema,
    suspendSchema: ApprovalSuspendPayloadSchema,
    resumeSchema: ApprovalResumePayloadSchema,
    execute: async ({ inputData, resumeData, suspend }) => {
      if (inputData.status !== "approval-requested") return inputData;
      if (!resumeData) {
        const store = (
          dependencies.openStore ?? createLibSqlOperationalStore
        )();
        let context;
        try {
          context = await readWorkflowPhase10Trace(store, {
            tenantId: inputData.plan.tenantId,
            incidentId: inputData.plan.incidentId,
            workflowRunId: inputData.workflowRunId,
          });
          const trace = startPhase10Boundary({
            boundary: "approval.await",
            tenantId: inputData.plan.tenantId,
            incidentId: inputData.plan.incidentId,
            runId: inputData.workflowRunId,
            correlationId: inputData.correlationId,
            requestId: context?.requestId ?? inputData.workflowRunId,
            ...(context ? { context } : {}),
            identifiers: { stepId: "await-approval", provider: "linear" },
          });
          trace.span.end({ attributes: { success: true } as never });
          if (context)
            await advanceWorkflowPhase10Trace(store, {
              tenantId: inputData.plan.tenantId,
              incidentId: inputData.plan.incidentId,
              workflowRunId: inputData.workflowRunId,
              previous: context,
              next: {
                ...trace.context,
                runId: inputData.workflowRunId,
                requestId: context.requestId,
              },
            });
          return suspend({
            incidentId: inputData.plan.incidentId,
            workflowRunId: inputData.workflowRunId,
            approvalId: inputData.approval.approvalId,
            planHashVersion: 1,
            planHash: inputData.plan.planHash,
            expiresAt: inputData.approval.expiresAt,
          });
        } finally {
          store.close();
        }
      }
      const parsedResume = ApprovalResumePayloadSchema.parse(resumeData);
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      let trace: ReturnType<typeof startPhase10Boundary> | undefined;
      try {
        const context = await readWorkflowPhase10Trace(store, {
          tenantId: inputData.plan.tenantId,
          incidentId: inputData.plan.incidentId,
          workflowRunId: inputData.workflowRunId,
        });
        trace = startPhase10Boundary({
          boundary: "approval.resume",
          tenantId: inputData.plan.tenantId,
          incidentId: inputData.plan.incidentId,
          runId: inputData.workflowRunId,
          correlationId: inputData.correlationId,
          requestId: inputData.workflowRunId,
          ...(context ? { context } : {}),
        });
        const authoritative = await readConsumedResumeReceipt(store, {
          resumeReceiptId: parsedResume.resumeReceiptId,
          tenantId: inputData.plan.tenantId,
          incidentId: inputData.plan.incidentId,
          workflowRunId: inputData.workflowRunId,
          approvalId: inputData.approval.approvalId,
        });
        const result = ApprovalResolvedResultSchema.parse({
          status: "approval-resolved",
          decision: inputData.decision,
          summary: inputData.summary,
          plan: inputData.plan,
          approval: inputData.approval,
          authoritative,
          workflowRunId: inputData.workflowRunId,
          correlationId: inputData.correlationId,
        });
        trace.span.end({ attributes: { success: true } as never });
        if (context)
          await advanceWorkflowPhase10Trace(store, {
            tenantId: inputData.plan.tenantId,
            incidentId: inputData.plan.incidentId,
            workflowRunId: inputData.workflowRunId,
            previous: context,
            next: {
              ...trace.context,
              runId: inputData.workflowRunId,
              requestId: context.requestId,
            },
          });
        return result;
      } catch (error) {
        trace?.span.error({ error: error as Error, endSpan: true });
        throw error;
      } finally {
        store.close();
      }
    },
  });
}
