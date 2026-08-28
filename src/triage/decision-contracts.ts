import { z } from "zod";

import {
  opaqueId,
  evidenceReference,
  longText,
  reference,
  runbookReference,
  sha256,
} from "../schemas/common.js";
import {
  ContainmentActionTypeSchema,
  ContainmentPlanSchema,
} from "../schemas/containment.js";
import { IncidentSeveritySchema } from "../schemas/incident.js";

export const PHASE5_POLICY_VERSION = 1;
export const PHASE5_PLAN_HASH_VERSION = 1;
export const PHASE5_PLAN_TTL_MS = 15 * 60 * 1_000;
export const PHASE5_MIN_CONFIDENCE = 0.8;
export const PHASE5_MAX_ACTIONS = 2;

export const Phase5ReasonCodeSchema = z.enum([
  "REQUIRED_EVIDENCE_MISSING",
  "REQUIRED_EVIDENCE_INCOMPLETE",
  "CONFIDENCE_BELOW_THRESHOLD",
  "MATERIAL_CONTRADICTION",
  "MODEL_DIVERGENCE",
  "MODEL_SCHEMA_INVALID",
  "MODEL_UNAVAILABLE",
  "TARGET_NOT_PROVEN",
  "BENIGN_EXPLANATION",
  "INTEGRITY_CHECK_FAILED",
  "SCOPE_CHECK_FAILED",
  "CLAIM_REJECTED",
  "ACTION_NOT_ALLOWED",
  "ACTION_DUPLICATE",
  "ACTION_CONFLICT",
  "ACTION_INPUT_INVALID",
  "PLAN_INVALID",
]);

export type Phase5ReasonCode = z.infer<typeof Phase5ReasonCodeSchema>;

export const SeverityAnalysisCandidateSchema = z
  .object({
    schemaVersion: z.literal(1),
    assessment: z.enum(["supports-policy", "uncertain", "contradicts-policy"]),
    factTokens: z
      .array(z.string().regex(/^fact-(?:[1-9]|[1-4][0-9])$/u))
      .max(48),
    rationaleCode: z.enum([
      "central-event",
      "benign-explanation",
      "insufficient-context",
    ]),
  })
  .strict();

export const SummaryAnalysisCandidateSchema = z
  .object({
    schemaVersion: z.literal(1),
    factTokens: z
      .array(z.string().regex(/^fact-(?:[1-9]|[1-4][0-9])$/u))
      .max(48),
    hypothesisCodes: z.array(z.enum(["known-false-positive"])).max(1),
  })
  .strict();

export const ContainmentCandidateSchema = z
  .object({
    actionType: ContainmentActionTypeSchema,
    targetToken: z.string().regex(/^target-[1-3]$/u),
    inputToken: z.string().regex(/^input-[1-4]$/u),
  })
  .strict();

export const ContainmentAnalysisCandidateSchema = z
  .object({
    schemaVersion: z.literal(1),
    actions: z.array(ContainmentCandidateSchema).min(1).max(PHASE5_MAX_ACTIONS),
  })
  .strict();

export const SeverityDecisionSchema = z
  .object({
    schemaVersion: z.literal(1),
    decisionId: opaqueId,
    incidentId: opaqueId,
    tenantId: opaqueId,
    workflowRunId: opaqueId,
    severity: IncidentSeveritySchema.exclude(["critical"]),
    effectiveConfidence: z.number().finite().min(0).max(1),
    rationale: z.string().trim().min(1).max(1_024),
    references: z.array(reference).min(1).max(32),
    runbookReference,
    policyVersion: z.literal(PHASE5_POLICY_VERSION),
    reasonCodes: z.array(Phase5ReasonCodeSchema).max(16),
  })
  .strict();

const Phase5FactClaimSchema = z
  .object({
    text: longText,
    references: z
      .array(reference)
      .min(1)
      .max(16)
      .refine(
        (references) =>
          references.some((item) => evidenceReference.safeParse(item).success),
        "facts require evidence",
      ),
  })
  .strict();

const Phase5HypothesisClaimSchema = z
  .object({ text: longText, references: z.array(reference).max(16) })
  .strict();

export const IncidentSummaryV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    incidentId: opaqueId,
    summary: longText,
    facts: z.array(Phase5FactClaimSchema).max(64),
    hypotheses: z.array(Phase5HypothesisClaimSchema).max(16),
  })
  .strict();

export const ClassificationStepResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("classified"),
      decision: SeverityDecisionSchema,
    })
    .strict(),
  phase5StopSchema("manual-review"),
  phase5StopSchema("blocked"),
]);

export const SummaryStepResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("summarized"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
    })
    .strict(),
  phase5StopSchema("manual-review"),
  phase5StopSchema("blocked"),
]);

export const ProposalStepResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("proposed"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      candidate: ContainmentAnalysisCandidateSchema,
    })
    .strict(),
  phase5StopSchema("manual-review"),
  phase5StopSchema("blocked"),
]);

export const ValidatedContainmentPlanSchema = ContainmentPlanSchema.safeExtend({
  planHashVersion: z.literal(PHASE5_PLAN_HASH_VERSION),
  planHash: sha256,
  actions: ContainmentPlanSchema.shape.actions.min(1).max(PHASE5_MAX_ACTIONS),
}).strict();

export const Phase5ResultSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("ready-for-approval"),
      decision: SeverityDecisionSchema,
      summary: IncidentSummaryV1Schema,
      plan: ValidatedContainmentPlanSchema,
    })
    .strict(),
  phase5StopSchema("manual-review"),
  phase5StopSchema("blocked"),
]);

function phase5StopSchema<const Status extends "manual-review" | "blocked">(
  status: Status,
) {
  return z
    .object({
      status: z.literal(status),
      incidentId: opaqueId,
      reasonCodes: z.array(Phase5ReasonCodeSchema).min(1).max(16),
    })
    .strict();
}

export type SeverityAnalysisCandidate = z.infer<
  typeof SeverityAnalysisCandidateSchema
>;
export type SummaryAnalysisCandidate = z.infer<
  typeof SummaryAnalysisCandidateSchema
>;
export type ContainmentAnalysisCandidate = z.infer<
  typeof ContainmentAnalysisCandidateSchema
>;
export type SeverityDecision = z.infer<typeof SeverityDecisionSchema>;
export type IncidentSummaryV1 = z.infer<typeof IncidentSummaryV1Schema>;
export type ClassificationStepResult = z.infer<
  typeof ClassificationStepResultSchema
>;
export type SummaryStepResult = z.infer<typeof SummaryStepResultSchema>;
export type ProposalStepResult = z.infer<typeof ProposalStepResultSchema>;
export type Phase5Result = z.infer<typeof Phase5ResultSchema>;
