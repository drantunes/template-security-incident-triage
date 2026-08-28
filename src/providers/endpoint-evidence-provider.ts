import type { EvidenceFact } from "../evidence/contracts.js";
import type {
  EndpointEvidenceProvider,
  SafeProviderCall,
} from "./evidence-provider.js";
import {
  executeMockInspection,
  type MockProviderOptions,
} from "./mock-evidence.js";

export class MockEndpointEvidenceProvider implements EndpointEvidenceProvider {
  readonly source = "endpoint" as const;
  readonly providerId = "mock-endpoint";
  readonly calls: SafeProviderCall[] = [];
  constructor(private readonly options: MockProviderOptions = {}) {}
  inspect(
    input: Parameters<EndpointEvidenceProvider["inspect"]>[0],
    options: Parameters<EndpointEvidenceProvider["inspect"]>[1],
  ) {
    return executeMockInspection({
      provider: "mock-endpoint",
      providerRef: "endpoint",
      request: input,
      signal: options.signal,
      attempt: options.attempt,
      behavior: this.options.behavior ?? "success",
      ...(this.options.release ? { release: this.options.release } : {}),
      ...(this.options.onStart ? { onStart: this.options.onStart } : {}),
      callLog: this.calls,
      facts: (request) =>
        endpointFacts(
          request.occurredAt,
          request.incidentKind,
          request.deviceId,
        ),
    });
  }
}

function endpointFacts(
  observedAt: string,
  incidentKind: string,
  deviceId?: string,
): readonly EvidenceFact[] {
  if (incidentKind !== "unknown_device_login")
    return [
      booleanFact(
        observedAt,
        "inspection-applicable",
        "endpoint.inspectionApplicable",
        false,
      ),
    ];
  const identifier = booleanFact(
    observedAt,
    "device-identifier-present",
    "device.identifierPresent",
    deviceId !== undefined,
    deviceId === undefined,
  );
  if (!deviceId) return [identifier];
  return [
    identifier,
    booleanFact(
      observedAt,
      "device-signature-valid",
      "device.signatureValid",
      true,
    ),
    booleanFact(
      observedAt,
      "device-authorized",
      "device.authorized",
      deviceId === "device-known-1",
    ),
  ];
}

function booleanFact(
  observedAt: string,
  semanticKey: string,
  factType: string,
  value: boolean,
  incomplete = false,
): EvidenceFact {
  return {
    semanticKey,
    observedAt,
    factType,
    value,
    confidence: 1,
    confidenceProvenance: "rule-v1",
    rawPayloadRef: `protected:endpoint:${semanticKey}`,
    sensitivity: "confidential",
    incomplete,
  };
}
