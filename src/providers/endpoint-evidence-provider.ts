import {
  EvidenceProviderResultSchema,
  type EvidenceFact,
} from "../evidence/contracts.js";
import type {
  EndpointEvidenceProvider,
  SafeProviderCall,
} from "./evidence-provider.js";
import type { EvidenceProviderInput } from "../evidence/contracts.js";
import {
  readDemoEvidenceBaseline,
  isDemoDeviceAuthorized,
  consumeDemoDeviceNonce,
  verifyDemoDevice,
} from "../demo/evidence-baseline.js";
import type { OperationalStore } from "../db/operational-store.js";
import {
  executeMockInspection,
  type MockProviderOptions,
} from "./mock-evidence.js";

export class MockEndpointEvidenceProvider implements EndpointEvidenceProvider {
  readonly source = "endpoint" as const;
  readonly providerId = "mock-endpoint";
  readonly calls: SafeProviderCall[] = [];
  private readonly usedNonces = new Set<string>();
  constructor(
    private readonly options: MockProviderOptions & {
      /** DB-backed F9 authority, when the caller has an owned local store. */
      openBaselineStore?: () => OperationalStore;
      /** F9 owns a persisted baseline; corruption must not activate legacy facts. */
      requireDemoBaseline?: boolean;
      /** Explicit fixture authority for pre-F9 mock harnesses. */
      verifyDeviceSignature?: (input: EvidenceProviderInput) => boolean;
    } = {},
  ) {}
  async inspect(
    input: Parameters<EndpointEvidenceProvider["inspect"]>[0],
    options: Parameters<EndpointEvidenceProvider["inspect"]>[1],
  ) {
    const baseline = await readDemoEvidenceBaseline(
      this.options.openBaselineStore,
      input,
    );
    if (this.options.requireDemoBaseline && !baseline)
      return EvidenceProviderResultSchema.parse({
        status: "invalid_response",
        provider: this.providerId,
        error: {
          code: "INVALID_RESPONSE",
          retryable: false,
          safeRef: `provider:endpoint:attempt-${options.attempt}`,
          attempt: options.attempt,
        },
      });
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
      facts: async (request) =>
        endpointFacts(
          request,
          baseline,
          this.usedNonces,
          await isDemoDeviceAuthorized(this.options.openBaselineStore, request),
          this.options.verifyDeviceSignature,
          this.options.requireDemoBaseline
            ? () =>
                baseline?.device
                  ? consumeDemoDeviceNonce(
                      this.options.openBaselineStore,
                      baseline.device,
                      request,
                    )
                  : Promise.resolve(false)
            : undefined,
        ),
    });
  }
}

async function endpointFacts(
  input: EvidenceProviderInput,
  baseline: Awaited<ReturnType<typeof readDemoEvidenceBaseline>>,
  usedNonces: Set<string>,
  authorized: boolean,
  verifyDeviceSignature:
    ((input: EvidenceProviderInput) => boolean) | undefined,
  consumeNonce: (() => Promise<boolean>) | undefined,
): Promise<readonly EvidenceFact[]> {
  const { occurredAt: observedAt, incidentKind, deviceId } = input;
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
      // Absence of authority is never a signature. Legacy fixture paths must
      // inject an explicit verifier instead of inheriting a permissive default.
      baseline?.device
        ? consumeNonce
          ? verifyDemoDevice(baseline.device, input, new Set()) &&
            (await consumeNonce())
          : verifyDemoDevice(baseline.device, input, usedNonces)
        : verifyDeviceSignature?.(input) === true,
    ),
    booleanFact(
      observedAt,
      "device-authorized",
      "device.authorized",
      authorized,
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
