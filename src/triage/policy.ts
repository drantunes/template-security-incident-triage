import type { InvestigationContext } from "../evidence/contracts.js";
import type { LoadedRunbook } from "../runbooks/loader.js";
import type { Evidence } from "../schemas/evidence.js";
import type { IncidentKind, IncidentSeverity } from "../schemas/incident.js";
import {
  PHASE5_MIN_CONFIDENCE,
  type Phase5ReasonCode,
} from "./decision-contracts.js";
import {
  evidenceRequirements,
  severityRules,
  type EvidenceRequirement,
} from "./policy-registry.js";

export type PolicyEvaluation = Readonly<{
  outcome: "classified" | "manual-review";
  severity?: Exclude<IncidentSeverity, "critical">;
  effectiveConfidence: number;
  requiredEvidence: readonly Evidence[];
  reasonCodes: readonly Phase5ReasonCode[];
  rationaleCode:
    "central-event" | "benign-explanation" | "insufficient-context";
}>;

export function evaluateSeverityPolicy(
  context: InvestigationContext,
  evidence: readonly Evidence[],
  contradictionCount: number,
): PolicyEvaluation {
  const rule = severityRules[context.incidentKind];
  const resolutions = rule.requiredEvidence.map((item) =>
    resolveEvidenceRequirement(evidence, item, context),
  );
  const reasons: Phase5ReasonCode[] = [];
  if (resolutions.some((item) => item.status === "missing"))
    reasons.push("REQUIRED_EVIDENCE_MISSING");
  if (resolutions.some((item) => item.status === "invalid"))
    reasons.push("REQUIRED_EVIDENCE_INCOMPLETE");
  const present = resolutions.flatMap((item) =>
    item.status === "valid" ? [item.evidence] : [],
  );
  const matched = resolutions.flatMap((item) =>
    "evidence" in item ? [item.evidence] : [],
  );
  const invalidResolution = resolutions.find((item) => item.status !== "valid");
  const effectiveConfidence =
    invalidResolution &&
    (invalidResolution.status === "missing" ||
      invalidResolution.reason !== "low-confidence")
      ? 0
      : matched.length
        ? Math.min(...matched.map((item) => item.confidence))
        : 0;
  if (
    resolutions.some(
      (item) => item.status === "invalid" && item.reason === "low-confidence",
    )
  )
    reasons.push("CONFIDENCE_BELOW_THRESHOLD");
  if (contradictionCount > 0) reasons.push("MATERIAL_CONTRADICTION");
  if (reasons.length > 0)
    return {
      outcome: "manual-review",
      effectiveConfidence,
      requiredEvidence: present,
      reasonCodes: [...new Set(reasons)],
      rationaleCode: "insufficient-context",
    };

  const facts = new Map(
    present.map((item) => [String(item.fact.factType), item] as const),
  );
  const benign = rule.benignExplanation(facts);
  const central = rule.centralEvent(facts);
  if (!benign && !central)
    return {
      outcome: "manual-review",
      effectiveConfidence,
      requiredEvidence: present,
      reasonCodes: ["REQUIRED_EVIDENCE_INCOMPLETE"],
      rationaleCode: "insufficient-context",
    };

  const aggravatingResolution = resolveEvidenceRequirement(
    evidence,
    rule.aggravatingEvidence,
    context,
  );
  const aggravating =
    aggravatingResolution.status === "valid" &&
    aggravatingResolution.evidence.fact.value === true;
  return {
    outcome: "classified",
    severity: benign ? "low" : aggravating ? "high" : "medium",
    effectiveConfidence,
    requiredEvidence: present,
    reasonCodes: [],
    rationaleCode: benign ? "benign-explanation" : "central-event",
  };
}

export function requiredFactTypes(kind: IncidentKind): readonly string[] {
  return severityRules[kind].requiredEvidence.map((item) => item.factType);
}

export function resolveTrustedFact(
  context: InvestigationContext,
  evidence: readonly Evidence[],
  factType:
    | "role.previous"
    | "session.subject"
    | "device.signatureValid"
    | "device.authorized",
): Evidence | undefined {
  const requirement = {
    "role.previous": evidenceRequirements.rolePrevious,
    "session.subject": evidenceRequirements.sessionSubject,
    "device.signatureValid": evidenceRequirements.deviceSignature,
    "device.authorized": evidenceRequirements.deviceAuthorized,
  }[factType];
  const resolution = resolveEvidenceRequirement(evidence, requirement, context);
  return resolution.status === "valid" ? resolution.evidence : undefined;
}

export function assertRunbookPolicy(
  kind: IncidentKind,
  runbook: LoadedRunbook,
): void {
  const requiredSection = runbook.sections[2]?.body ?? "";
  const severitySection = runbook.sections[3]?.body ?? "";
  const rule = severityRules[kind];
  if (
    !rule.requiredPhrases.every((phrase) => requiredSection.includes(phrase)) ||
    !rule.severityPhrases.every((phrase) => severitySection.includes(phrase))
  )
    throw new Error("Active runbook does not match policy registry v1");
}

export type RequirementResolution =
  | Readonly<{ status: "valid"; evidence: Evidence }>
  | Readonly<{ status: "missing" }>
  | Readonly<{
      status: "invalid";
      evidence: Evidence;
      reason:
        "duplicate" | "incomplete" | "low-confidence" | "provenance" | "value";
    }>;

export function resolveEvidenceRequirement(
  evidence: readonly Evidence[],
  requirement: EvidenceRequirement,
  context: InvestigationContext,
): RequirementResolution {
  const matches = evidence.filter(
    (item) => item.fact.factType === requirement.factType,
  );
  if (matches.length === 0) return { status: "missing" };
  if (matches.length !== 1)
    return { status: "invalid", evidence: matches[0]!, reason: "duplicate" };
  const item = matches[0]!;
  if (item.incomplete)
    return { status: "invalid", evidence: item, reason: "incomplete" };
  if (item.confidence < PHASE5_MIN_CONFIDENCE)
    return { status: "invalid", evidence: item, reason: "low-confidence" };
  const provenance = item.fact.confidenceProvenance;
  if (
    !requirement.sources.includes(item.source) ||
    !requirement.providers.includes(item.provider) ||
    (provenance !== "provider" && provenance !== "rule-v1") ||
    !requirement.provenances.includes(provenance)
  )
    return { status: "invalid", evidence: item, reason: "provenance" };
  if (!requirement.valueIsValid(item.fact.value, context))
    return { status: "invalid", evidence: item, reason: "value" };
  return { status: "valid", evidence: item };
}
