import { describe, expect, it } from "vitest";

import { readPhase8Config } from "../../src/env.js";
import { createPhase8GeoIpProvider } from "../../src/providers/runtime-factory.js";

const states = {
  received: "state_received",
  investigating: "state_investigating",
  awaiting_approval: "state_awaiting",
  approved: "state_approved",
  rejected: "state_rejected",
  containing: "state_containing",
  contained: "state_contained",
  failed: "state_failed",
  closed: "state_closed",
};

describe("Phase 8 staging harnesses (hermetic, default-deny)", () => {
  it("rejects each real adapter until staging, its flag, confirmation values, and allowlists are present", () => {
    expect(() =>
      readPhase8Config({ DEMO_MODE: "mock", WORKOS_PROVIDER_ENABLED: "true" }),
    ).toThrow("Real providers require staging mode.");
    expect(() =>
      readPhase8Config({
        DEMO_MODE: "staging",
        IPINFO_PROVIDER_ENABLED: "true",
      }),
    ).toThrow("IPinfo provider configuration is incomplete.");
    expect(() =>
      readPhase8Config({
        DEMO_MODE: "staging",
        LINEAR_PROVIDER_ENABLED: "true",
      }),
    ).toThrow("Invalid LINEAR_SEVERITY_LABEL_IDS_JSON.");
    expect(() =>
      readPhase8Config({
        DEMO_MODE: "staging",
        UPSTASH_PUBSUB_ENABLED: "true",
        UPSTASH_REDIS_URL: "<rediss_upstash_endpoint>",
      }),
    ).toThrow("Upstash provider configuration is incomplete.");
    expect(() =>
      readPhase8Config({
        DEMO_MODE: "staging",
        WORKOS_PROVIDER_ENABLED: "true",
        WEBHOOKS_ENABLED: "true",
        WORKOS_API_KEY: "fake-workos-api-key",
        WORKOS_WEBHOOK_SECRET: "fake-workos-webhook-secret",
        WORKOS_STAGING_ORGANIZATION_ID: "tenant_1",
        WORKOS_STAGING_ALLOWED_USER_IDS: "<user_id>",
        WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "admin",
      }),
    ).toThrow("Invalid WORKOS_STAGING_ALLOWED_USER_IDS.");
    expect(
      readPhase8Config({
        DEMO_MODE: "staging",
        WORKOS_PROVIDER_ENABLED: "true",
        WEBHOOKS_ENABLED: "true",
        WORKOS_API_KEY: "fake-workos-api-key",
        WORKOS_WEBHOOK_SECRET: "fake-workos-webhook-secret",
        WORKOS_STAGING_ORGANIZATION_ID: "tenant_1",
        WORKOS_STAGING_ALLOWED_USER_IDS: "user_1",
        WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "admin",
      }).workos.enabled,
    ).toBe(true);
  });

  it("uses injected fakes for the IPinfo staging harness and performs no network", async () => {
    const config = readPhase8Config({
      DEMO_MODE: "staging",
      IPINFO_PROVIDER_ENABLED: "true",
      IPINFO_TOKEN: "fake-ipinfo-token",
      GEOIP_CACHE_HMAC_KEY:
        "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      GEOIP_CACHE_HMAC_KEY_VERSION: "hmac-sha256-v1",
    });
    let calls = 0;
    const provider = createPhase8GeoIpProvider(config, {
      transport: async () => {
        calls += 1;
        return { status: 200, json: async () => ({ country_code: "BR" }) };
      },
    });
    await expect(
      provider?.lookup({
        tenantId: "tenant_1",
        ip: "8.8.8.8",
        deadline: new Date(Date.now() + 100),
      }),
    ).resolves.toMatchObject({ outcome: "known", countryCode: "BR" });
    expect(calls).toBe(1);
  });

  it("accepts complete Linear and Upstash staging fixtures without connecting to either service", () => {
    const config = readPhase8Config({
      DEMO_MODE: "staging",
      LINEAR_PROVIDER_ENABLED: "true",
      LINEAR_API_KEY: "fake-linear-api-key",
      LINEAR_WORKSPACE_ID: "workspace_1",
      LINEAR_TEAM_ID: "team_1",
      LINEAR_SEVERITY_LABEL_IDS_JSON: JSON.stringify({
        low: "l",
        medium: "m",
        high: "h",
        critical: "c",
      }),
      LINEAR_STATUS_STATE_IDS_JSON: JSON.stringify(states),
      LINEAR_INTERNAL_BASE_URL: "https://incidents.example.test/base",
      UPSTASH_PUBSUB_ENABLED: "true",
      UPSTASH_REDIS_URL: "rediss://token@upstash.example.test:6379",
    });
    expect(config.linear.enabled).toBe(true);
    expect(config.upstash.enabled).toBe(true);
  });
});
