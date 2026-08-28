import type { EvidenceFact } from "../evidence/contracts.js";
import type {
  CloudEvidenceProvider,
  SafeProviderCall,
} from "./evidence-provider.js";
import {
  executeMockInspection,
  type MockProviderOptions,
} from "./mock-evidence.js";

export class MockCloudEvidenceProvider implements CloudEvidenceProvider {
  readonly source = "cloud" as const;
  readonly providerId = "mock-cloud";
  readonly calls: SafeProviderCall[] = [];
  constructor(private readonly options: MockProviderOptions = {}) {}
  inspect(
    input: Parameters<CloudEvidenceProvider["inspect"]>[0],
    options: Parameters<CloudEvidenceProvider["inspect"]>[1],
  ) {
    return executeMockInspection({
      provider: "mock-cloud",
      providerRef: "cloud",
      request: input,
      signal: options.signal,
      attempt: options.attempt,
      behavior: this.options.behavior ?? "success",
      ...(this.options.release ? { release: this.options.release } : {}),
      ...(this.options.onStart ? { onStart: this.options.onStart } : {}),
      callLog: this.calls,
      facts: (request) =>
        cloudFacts(
          request.occurredAt,
          request.incidentKind,
          request.ip !== undefined,
        ),
    });
  }
}

function cloudFacts(
  observedAt: string,
  kind: string,
  ipPresent: boolean,
): readonly EvidenceFact[] {
  const country = kind === "disallowed_country_login" ? "CA" : "US";
  return [
    ...(ipPresent
      ? [fact(observedAt, "observed-country", "login.country", country)]
      : []),
    fact(observedAt, "allowed-country", "policy.allowedCountry", "US"),
    ...(kind === "disallowed_country_login"
      ? [
          booleanFact(
            observedAt,
            "source-ip-present",
            "login.ipPresent",
            ipPresent,
          ),
        ]
      : []),
    ...(kind === "disallowed_country_login" || kind === "unknown_device_login"
      ? [
          booleanFact(
            observedAt,
            "abnormal-session-history",
            "session.abnormalHistory",
            false,
          ),
        ]
      : []),
  ];
}

function booleanFact(
  observedAt: string,
  semanticKey: string,
  factType: string,
  value: boolean,
): EvidenceFact {
  return {
    semanticKey,
    observedAt,
    factType,
    value,
    confidence: 1,
    confidenceProvenance: "rule-v1",
    rawPayloadRef: `protected:cloud:${semanticKey}`,
    sensitivity: "confidential",
    incomplete: false,
  };
}

function fact(
  observedAt: string,
  semanticKey: string,
  factType: string,
  value: string,
): EvidenceFact {
  return {
    semanticKey,
    observedAt,
    factType,
    value,
    confidence: factType === "login.country" ? 0.8 : 1,
    confidenceProvenance: factType === "login.country" ? "provider" : "rule-v1",
    rawPayloadRef: `protected:cloud:${semanticKey}`,
    sensitivity: "confidential",
    incomplete: false,
  };
}
