import {
  EvidenceProviderResultSchema,
  type EvidenceFact,
} from "../evidence/contracts.js";
import { readDemoEvidenceBaseline } from "../demo/evidence-baseline.js";
import type { OperationalStore } from "../db/operational-store.js";
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
  constructor(
    private readonly options: MockProviderOptions & {
      countryByIp?: Readonly<Record<string, "US" | "CA">>;
      allowedCountry?: "US" | "CA";
      openBaselineStore?: () => OperationalStore;
      /** F9 owns a persisted baseline; corruption must not activate legacy facts. */
      requireDemoBaseline?: boolean;
    } = {},
  ) {}
  async inspect(
    input: Parameters<CloudEvidenceProvider["inspect"]>[0],
    options: Parameters<CloudEvidenceProvider["inspect"]>[1],
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
          safeRef: `provider:cloud:attempt-${options.attempt}`,
          attempt: options.attempt,
        },
      });
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
      facts: async (request) =>
        cloudFacts(
          request.occurredAt,
          request.incidentKind,
          request.ip,
          baseline,
          this.options,
        ),
    });
  }
}

function cloudFacts(
  observedAt: string,
  kind: string,
  ip: string | undefined,
  baseline: Awaited<ReturnType<typeof readDemoEvidenceBaseline>>,
  options: Readonly<{
    countryByIp?: Readonly<Record<string, "US" | "CA">>;
    allowedCountry?: "US" | "CA";
  }>,
): readonly EvidenceFact[] {
  const country = baseline?.cloud
    ? ip
      ? baseline.cloud.countryByIp[ip]
      : undefined
    : options.countryByIp
      ? ip
        ? options.countryByIp[ip]
        : undefined
      : kind === "disallowed_country_login"
        ? "CA"
        : "US";
  const ipPresent = ip !== undefined;
  return [
    ...(ipPresent && country
      ? [fact(observedAt, "observed-country", "login.country", country)]
      : []),
    fact(
      observedAt,
      "allowed-country",
      "policy.allowedCountry",
      baseline?.cloud?.allowedCountry ?? options.allowedCountry ?? "US",
    ),
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
            baseline?.cloud?.abnormalHistory ?? false,
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
