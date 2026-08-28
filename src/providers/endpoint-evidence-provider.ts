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
      facts: (request) => endpointFacts(request.occurredAt, request.deviceId),
    });
  }
}

function endpointFacts(
  observedAt: string,
  deviceId?: string,
): readonly EvidenceFact[] {
  return [
    {
      semanticKey: "device-signature-valid",
      observedAt,
      factType: "device.signatureValid",
      value: true,
      confidence: 1,
      confidenceProvenance: "rule-v1",
      rawPayloadRef: "protected:endpoint:signature",
      sensitivity: "confidential",
      incomplete: false,
    },
    {
      semanticKey: "device-authorized",
      observedAt,
      factType: "device.authorized",
      value: deviceId === undefined ? false : deviceId === "device-known-1",
      confidence: 1,
      confidenceProvenance: "rule-v1",
      rawPayloadRef: "protected:endpoint:allowlist",
      sensitivity: "confidential",
      incomplete: deviceId === undefined,
    },
  ];
}
