import type { Alert } from "../../src/schemas/alert.js";
import type { ApprovalRequest } from "../../src/schemas/approval.js";
import type { ContainmentPlan } from "../../src/schemas/containment.js";

export const firstTimestamp = "2026-08-27T12:00:00.000Z";
export const secondTimestamp = "2026-08-27T12:01:00.000Z";
export const expiryTimestamp = "2026-08-27T13:00:00.000Z";
export const planHash = "a".repeat(64);

export function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    schemaVersion: 1,
    alertId: "alert-1",
    source: "workos",
    sourceEventId: "source-event-1",
    kind: "unauthorized_privilege_change",
    occurredAt: firstTimestamp,
    tenantId: "tenant-1",
    subjectId: "subject-1",
    actor: { id: "actor-1", type: "user" },
    target: { id: "subject-1", type: "user" },
    changes: { previousRole: "member", nextRole: "admin" },
    rawPayloadRef: "protected://alerts/1",
    idempotencyKey: "alert-idempotency-1",
    ...overrides,
  };
}

export function makePlan(
  overrides: Partial<ContainmentPlan> = {},
): ContainmentPlan {
  return {
    schemaVersion: 1,
    planId: "plan-1",
    incidentId: "incident-1",
    tenantId: "tenant-1",
    planVersion: 1,
    planHashVersion: 1,
    planHash,
    createdAt: secondTimestamp,
    expiresAt: expiryTimestamp,
    actions: [
      {
        actionId: "action-1",
        type: "restore_previous_role",
        targetId: "subject-1",
        input: { role: "member" },
        impact: "Restores the previous authorized role.",
        preconditions: ["Current role is admin."],
        rollback: "Restore the admin role after review.",
        verification: "Confirm the subject role is member.",
      },
    ],
    ...overrides,
  };
}

export function makeApprovalRequest(
  overrides: Partial<ApprovalRequest> = {},
): ApprovalRequest {
  return {
    schemaVersion: 1,
    approvalId: "approval-1",
    planId: "plan-1",
    incidentId: "incident-1",
    tenantId: "tenant-1",
    planHashVersion: 1,
    planHash,
    requestedAt: secondTimestamp,
    expiresAt: expiryTimestamp,
    status: "pending",
    ...overrides,
  };
}
