import type { InvestigationContext } from "../evidence/contracts.js";
import type { Evidence, EvidenceSource } from "../schemas/evidence.js";
import type { IncidentKind } from "../schemas/incident.js";

type ConfidenceProvenance = "provider" | "rule-v1";

export type EvidenceRequirement = Readonly<{
  factType: string;
  sources: readonly EvidenceSource[];
  providers: readonly string[];
  provenances: readonly ConfidenceProvenance[];
  valueIsValid: (value: unknown, context: InvestigationContext) => boolean;
}>;

type SeverityRule = Readonly<{
  requiredEvidence: readonly EvidenceRequirement[];
  requiredPhrases: readonly string[];
  severityPhrases: readonly string[];
  centralEvent: (facts: ReadonlyMap<string, Evidence>) => boolean;
  benignExplanation: (facts: ReadonlyMap<string, Evidence>) => boolean;
  aggravatingEvidence: EvidenceRequirement;
}>;

const provider = ["provider"] as const;
const rule = ["rule-v1"] as const;
const identity = ["identity"] as const;
const endpoint = ["endpoint"] as const;
const cloud = ["cloud"] as const;
const identityProviders = ["mock-identity"] as const;
const endpointProviders = ["mock-endpoint"] as const;
const cloudProviders = ["mock-cloud"] as const;
const nonEmptyString = (value: unknown) =>
  typeof value === "string" && value.trim().length > 0;
const booleanValue = (value: unknown) => typeof value === "boolean";
const knownCountry = (value: unknown) => value === "US" || value === "CA";

export const evidenceRequirements = {
  rolePrevious: requirement(
    "role.previous",
    identity,
    identityProviders,
    provider,
    (value) =>
      typeof value === "string" &&
      ["admin", "member", "viewer"].includes(value),
  ),
  roleCurrent: requirement(
    "role.current",
    identity,
    identityProviders,
    provider,
    (value) =>
      typeof value === "string" &&
      ["admin", "member", "viewer"].includes(value),
  ),
  actorId: requirement(
    "actor.id",
    identity,
    identityProviders,
    provider,
    nonEmptyString,
  ),
  changeApproved: requirement(
    "change.approved",
    identity,
    identityProviders,
    rule,
    booleanValue,
  ),
  sessionActive: requirement(
    "session.active",
    identity,
    identityProviders,
    rule,
    (value, context) => context.sessionId !== undefined && booleanValue(value),
  ),
  ipPresent: requirement(
    "login.ipPresent",
    cloud,
    cloudProviders,
    rule,
    (value, context) => value === true && context.ip !== undefined,
  ),
  loginCountry: requirement(
    "login.country",
    cloud,
    cloudProviders,
    provider,
    (value, context) => context.ip !== undefined && knownCountry(value),
  ),
  allowedCountry: requirement(
    "policy.allowedCountry",
    cloud,
    cloudProviders,
    rule,
    (value) => value === "US",
  ),
  sessionSubject: requirement(
    "session.subject",
    identity,
    identityProviders,
    provider,
    (value, context) =>
      context.sessionId !== undefined && value === context.subjectId,
  ),
  abnormalHistory: requirement(
    "session.abnormalHistory",
    cloud,
    cloudProviders,
    rule,
    (value, context) => context.sessionId !== undefined && booleanValue(value),
  ),
  deviceIdentifier: requirement(
    "device.identifierPresent",
    endpoint,
    endpointProviders,
    rule,
    (value, context) => value === true && context.deviceId !== undefined,
  ),
  deviceSignature: requirement(
    "device.signatureValid",
    endpoint,
    endpointProviders,
    rule,
    (value, context) => context.deviceId !== undefined && booleanValue(value),
  ),
  deviceAuthorized: requirement(
    "device.authorized",
    endpoint,
    endpointProviders,
    rule,
    (value, context) => context.deviceId !== undefined && booleanValue(value),
  ),
} as const;

export const severityRules: Readonly<Record<IncidentKind, SeverityRule>> = {
  unauthorized_privilege_change: {
    requiredEvidence: [
      evidenceRequirements.rolePrevious,
      evidenceRequirements.roleCurrent,
      evidenceRequirements.actorId,
      evidenceRequirements.changeApproved,
    ],
    requiredPhrases: [
      "previous identity snapshot",
      "current role-change event",
      "actor identifier",
      "event time",
    ],
    severityPhrases: ["unapproved administrative role", "active sessions"],
    centralEvent: (facts) =>
      value(facts, "role.previous") !== value(facts, "role.current") &&
      value(facts, "role.current") === "admin" &&
      value(facts, "change.approved") === false,
    benignExplanation: (facts) =>
      value(facts, "role.previous") === value(facts, "role.current"),
    aggravatingEvidence: evidenceRequirements.sessionActive,
  },
  disallowed_country_login: {
    requiredEvidence: [
      evidenceRequirements.ipPresent,
      evidenceRequirements.loginCountry,
      evidenceRequirements.allowedCountry,
      evidenceRequirements.sessionSubject,
      evidenceRequirements.abnormalHistory,
    ],
    requiredPhrases: [
      "source IP reference",
      "GeoIP result",
      "tenant country policy",
      "explicit session",
      "recent login history",
    ],
    severityPhrases: ["disallowed country", "abnormal session history"],
    centralEvent: (facts) => value(facts, "login.country") !== "US",
    benignExplanation: (facts) => value(facts, "login.country") === "US",
    aggravatingEvidence: evidenceRequirements.abnormalHistory,
  },
  unknown_device_login: {
    requiredEvidence: [
      evidenceRequirements.deviceIdentifier,
      evidenceRequirements.deviceSignature,
      evidenceRequirements.deviceAuthorized,
      evidenceRequirements.sessionSubject,
      evidenceRequirements.abnormalHistory,
    ],
    requiredPhrases: [
      "device identifier",
      "valid application signature",
      "authorized-device list",
      "explicit session",
      "recent login history",
    ],
    severityPhrases: ["unknown signed device", "abnormal session history"],
    centralEvent: (facts) =>
      value(facts, "device.signatureValid") === true &&
      value(facts, "device.authorized") === false,
    benignExplanation: (facts) => value(facts, "device.authorized") === true,
    aggravatingEvidence: evidenceRequirements.abnormalHistory,
  },
};

export const claimRequirements: Readonly<
  Record<IncidentKind, readonly EvidenceRequirement[]>
> = {
  unauthorized_privilege_change: [
    evidenceRequirements.rolePrevious,
    evidenceRequirements.roleCurrent,
    evidenceRequirements.actorId,
    evidenceRequirements.changeApproved,
    evidenceRequirements.sessionSubject,
    evidenceRequirements.sessionActive,
  ],
  disallowed_country_login: [
    evidenceRequirements.ipPresent,
    evidenceRequirements.loginCountry,
    evidenceRequirements.allowedCountry,
    evidenceRequirements.sessionSubject,
    evidenceRequirements.abnormalHistory,
  ],
  unknown_device_login: [
    evidenceRequirements.deviceIdentifier,
    evidenceRequirements.deviceSignature,
    evidenceRequirements.deviceAuthorized,
    evidenceRequirements.sessionSubject,
    evidenceRequirements.abnormalHistory,
  ],
};

function requirement(
  factType: string,
  sources: readonly EvidenceSource[],
  providers: readonly string[],
  provenances: readonly ConfidenceProvenance[],
  valueIsValid: EvidenceRequirement["valueIsValid"],
): EvidenceRequirement {
  return { factType, sources, providers, provenances, valueIsValid };
}

function value(
  facts: ReadonlyMap<string, Evidence>,
  factType: string,
): unknown {
  return facts.get(factType)?.fact.value;
}
