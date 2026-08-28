import type { EvidenceFact } from "../evidence/contracts.js";
import type {
  IdentityEvidenceProvider,
  SafeProviderCall,
} from "./evidence-provider.js";
import {
  executeMockInspection,
  type MockProviderOptions,
} from "./mock-evidence.js";

export class MockIdentityEvidenceProvider implements IdentityEvidenceProvider {
  readonly source = "identity" as const;
  readonly providerId = "mock-identity";
  readonly calls: SafeProviderCall[] = [];
  constructor(private readonly options: MockProviderOptions = {}) {}

  inspect(
    input: Parameters<IdentityEvidenceProvider["inspect"]>[0],
    options: Parameters<IdentityEvidenceProvider["inspect"]>[1],
  ) {
    return executeMockInspection({
      provider: "mock-identity",
      providerRef: "identity",
      request: input,
      signal: options.signal,
      attempt: options.attempt,
      behavior: this.options.behavior ?? "success",
      ...(this.options.release ? { release: this.options.release } : {}),
      ...(this.options.onStart ? { onStart: this.options.onStart } : {}),
      callLog: this.calls,
      facts: identityFacts,
    });
  }
}

function identityFacts(
  input: Parameters<IdentityEvidenceProvider["inspect"]>[0],
): readonly EvidenceFact[] {
  if (input.incidentKind === "unauthorized_privilege_change") {
    return [
      fact(input.occurredAt, "previous-role", "role.previous", "member"),
      fact(input.occurredAt, "current-role", "role.current", "admin"),
      fact(input.occurredAt, "actor", "actor.id", "synthetic-admin-1"),
      booleanFact(
        input.occurredAt,
        "approved-change",
        "change.approved",
        false,
      ),
      ...(input.sessionId
        ? [
            fact(
              input.occurredAt,
              "session-subject",
              "session.subject",
              input.subjectId,
            ),
            booleanFact(
              input.occurredAt,
              "session-active",
              "session.active",
              true,
            ),
          ]
        : []),
    ];
  }
  return [
    fact(
      input.occurredAt,
      "session-subject",
      "session.subject",
      input.subjectId,
    ),
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
    rawPayloadRef: `protected:identity:${semanticKey}`,
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
    confidence: 1,
    confidenceProvenance: "provider",
    rawPayloadRef: `protected:identity:${semanticKey}`,
    sensitivity: "confidential",
    incomplete: false,
  };
}
