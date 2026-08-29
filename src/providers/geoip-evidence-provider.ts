import { createHash } from "node:crypto";

import {
  EvidenceProviderResultSchema,
  type EvidenceProviderInput,
} from "../evidence/contracts.js";
import type { IdentityEvidenceProvider } from "./evidence-provider.js";
import type { GeoIpProvider } from "./geoip-provider.js";

/** Adds the approved, minimal GeoIP projection to identity gathering only. */
export class GeoIpIdentityEvidenceProvider implements IdentityEvidenceProvider {
  readonly source = "identity" as const;
  readonly providerId = "identity-geoip";
  constructor(
    private readonly options: Readonly<{
      base: IdentityEvidenceProvider;
      geoip: GeoIpProvider;
      timeoutMs: number;
    }>,
  ) {}

  async inspect(
    input: EvidenceProviderInput,
    options: Readonly<{ signal: AbortSignal; attempt: 1 | 2 }>,
  ): Promise<unknown> {
    const base = EvidenceProviderResultSchema.parse(
      await this.options.base.inspect(input, options),
    );
    // Without a known GeoIP projection this wrapper is transparent. In
    // particular, relabeling the base result would falsely attribute WorkOS
    // facts (and even failures) to GeoIP when nothing was added.
    if (!input.ip) return base;
    const geo = await this.options.geoip.lookup({
      tenantId: input.tenantId,
      ip: input.ip,
      deadline: new Date(Date.now() + this.options.timeoutMs),
      signal: options.signal,
    });
    if (geo.outcome !== "known") return base;
    const rawPayloadRef = `sha256:${createHash("sha256")
      .update(JSON.stringify(geo), "utf8")
      .digest("hex")}`;
    return EvidenceProviderResultSchema.parse({
      status: "success",
      // The result-level provider remains compatible with v1. Fact-level
      // origins below keep WorkOS facts attributable to WorkOS when combined.
      provider: base.status === "success" ? base.provider : this.providerId,
      facts: [
        ...(base.status === "success" ? base.facts : []),
        {
          semanticKey: "login.ip_present",
          factType: "login.ipPresent",
          value: true,
          observedAt: input.occurredAt,
          confidence: 1,
          confidenceProvenance: "rule-v1",
          rawPayloadRef: `protected:identity-geoip:ip-present`,
          sensitivity: "confidential",
          incomplete: false,
          provider: this.providerId,
        },
        {
          semanticKey: "login.country",
          factType: "login.country",
          value: geo.countryCode,
          observedAt: geo.observedAt,
          confidence: geo.confidence,
          confidenceProvenance: "policy-v1",
          rawPayloadRef,
          sensitivity: "internal",
          incomplete: false,
          provider: this.providerId,
        },
        ...(geo.asn
          ? [
              {
                semanticKey: "geoip.asn",
                factType: "geoip.asn",
                value: geo.asn,
                observedAt: geo.observedAt,
                confidence: geo.confidence,
                confidenceProvenance: "rule-v1" as const,
                rawPayloadRef,
                sensitivity: "internal" as const,
                incomplete: false,
                provider: this.providerId,
              },
            ]
          : []),
      ],
    });
  }
}
