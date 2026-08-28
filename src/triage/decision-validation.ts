import { DomainError } from "../domain/errors.js";
import { canonicalJson } from "../evidence/canonicalize.js";
import { sha256 } from "../runbooks/hashes.js";
import type { DecisionContext } from "./decision-context.js";
import {
  PHASE5_POLICY_VERSION,
  SeverityDecisionSchema,
  type SeverityDecision,
} from "./decision-contracts.js";
import { evaluateSeverityPolicy } from "./policy.js";

export function buildSeverityDecision(
  context: DecisionContext,
): SeverityDecision {
  const evaluation = evaluateSeverityPolicy(
    context.correlation.context,
    context.evidence,
    context.correlation.contradictions.length,
  );
  if (evaluation.outcome !== "classified" || !evaluation.severity)
    throw new DomainError("VALIDATION_FAILED");
  const scope = context.correlation.context;
  const references = [
    ...evaluation.requiredEvidence.map(
      (item) => `[evidence:${item.evidenceId}]`,
    ),
    `[runbook:${context.runbook.metadata.id}@${context.runbook.metadata.version}]`,
  ];
  return SeverityDecisionSchema.parse({
    schemaVersion: 1,
    decisionId: `decision_${sha256(
      canonicalJson({
        namespace: "phase5-severity-v1",
        incidentId: scope.incidentId,
        workflowRunId: scope.workflowRunId,
        severity: evaluation.severity,
        references,
      }),
    )}`,
    incidentId: scope.incidentId,
    tenantId: scope.tenantId,
    workflowRunId: scope.workflowRunId,
    severity: evaluation.severity,
    effectiveConfidence: evaluation.effectiveConfidence,
    rationale:
      evaluation.rationaleCode === "benign-explanation"
        ? "Integrity-verified evidence supports the documented benign condition."
        : "Integrity-verified evidence supports the runbook central-event rule.",
    references,
    runbookReference: references.at(-1),
    policyVersion: PHASE5_POLICY_VERSION,
    reasonCodes: [],
  });
}

export function assertSeverityDecision(
  context: DecisionContext,
  decision: SeverityDecision,
): void {
  if (canonicalJson(decision) !== canonicalJson(buildSeverityDecision(context)))
    throw new DomainError("CONFLICT");
}
