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
        return suspend({
          incidentId: inputData.plan.incidentId,
          workflowRunId: inputData.workflowRunId,
          approvalId: inputData.approval.approvalId,
          planHashVersion: 1,
          planHash: inputData.plan.planHash,
          expiresAt: inputData.approval.expiresAt,
        });
      }
      const parsedResume = ApprovalResumePayloadSchema.parse(resumeData);
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        const authoritative = await readConsumedResumeReceipt(store, {
          resumeReceiptId: parsedResume.resumeReceiptId,
          tenantId: inputData.plan.tenantId,
          incidentId: inputData.plan.incidentId,
          workflowRunId: inputData.workflowRunId,
          approvalId: inputData.approval.approvalId,
        });
        return ApprovalResolvedResultSchema.parse({
          status: "approval-resolved",
          decision: inputData.decision,
          summary: inputData.summary,
          plan: inputData.plan,
          approval: inputData.approval,
          authoritative,
          workflowRunId: inputData.workflowRunId,
          correlationId: inputData.correlationId,
        });
      } finally {
        store.close();
      }
    },
  });
}
