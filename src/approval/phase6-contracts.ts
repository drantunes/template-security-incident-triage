import { z } from "zod";

import {
  ApprovalRequestSchema,
  AuthoritativeApprovalResultSchema,
  ExpiredApprovalResultSchema,
} from "../schemas/approval.js";
import {
  ContainmentActionOutcomeSchema,
  ContainmentPlanSchema,
} from "../schemas/containment.js";
import { opaqueId } from "../schemas/common.js";
import {
  IncidentSummaryV1Schema,
  Phase5ResultSchema,
  SeverityDecisionSchema,
} from "../triage/decision-contracts.js";

const phase5ManualReview = Phase5ResultSchema.options[1];
const phase5Blocked = Phase5ResultSchema.options[2];

export const ApprovalRequestedResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("approval-requested"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      approval: ApprovalRequestSchema,
      workflowRunId: opaqueId,
      correlationId: opaqueId,
    })
    .strict(),
  phase5ManualReview,
  phase5Blocked,
]);

export const ApprovalResolvedResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("approval-resolved"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      approval: ApprovalRequestSchema,
      authoritative: z.union([
        AuthoritativeApprovalResultSchema,
        ExpiredApprovalResultSchema,
      ]),
      workflowRunId: opaqueId,
      correlationId: opaqueId,
    })
    .strict(),
  phase5ManualReview,
  phase5Blocked,
]);

export const ContainmentExecutionResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("expired"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      authoritative: ExpiredApprovalResultSchema,
      workflowRunId: opaqueId,
      correlationId: opaqueId,
    })
    .strict(),
  z
    .object({
      status: z.literal("rejected"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      authoritative: AuthoritativeApprovalResultSchema,
      workflowRunId: opaqueId,
      correlationId: opaqueId,
    })
    .strict(),
  z
    .object({
      status: z.literal("containment-succeeded"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      authoritative: AuthoritativeApprovalResultSchema,
      workflowRunId: opaqueId,
      correlationId: opaqueId,
      outcomes: z.array(ContainmentActionOutcomeSchema).min(1).max(2),
    })
    .strict(),
  z
    .object({
      status: z.literal("containment-failed"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ContainmentPlanSchema,
      authoritative: AuthoritativeApprovalResultSchema,
      workflowRunId: opaqueId,
      correlationId: opaqueId,
      partial: z.boolean(),
      outcomes: z.array(ContainmentActionOutcomeSchema).min(1).max(2),
    })
    .strict(),
  phase5ManualReview,
  phase5Blocked,
]);

export const Phase6ResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("expired"),
      incidentId: opaqueId,
      approvalId: opaqueId,
    })
    .strict(),
  z
    .object({
      status: z.literal("rejected"),
      incidentId: opaqueId,
      approvalId: opaqueId,
    })
    .strict(),
  z
    .object({
      status: z.literal("contained"),
      incidentId: opaqueId,
      approvalId: opaqueId,
      outcomes: z.array(ContainmentActionOutcomeSchema).min(1).max(2),
    })
    .strict(),
  z
    .object({
      status: z.literal("failed"),
      incidentId: opaqueId,
      approvalId: opaqueId,
      partial: z.boolean(),
      outcomes: z.array(ContainmentActionOutcomeSchema).min(1).max(2),
    })
    .strict(),
  phase5ManualReview,
  phase5Blocked,
]);

export type ApprovalRequestedResult = z.infer<
  typeof ApprovalRequestedResultSchema
>;
export type ApprovalResolvedResult = z.infer<
  typeof ApprovalResolvedResultSchema
>;
export type ContainmentExecutionResult = z.infer<
  typeof ContainmentExecutionResultSchema
>;
