import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  readPhase2Config,
  readPhase6Config,
  readPhase7Config,
} from "../../src/env.js";
import { readPhase8Config } from "../../src/config/phase8.js";

describe("mock environment example", () => {
  it("starts with webhooks disabled and no real-provider opt-in", async () => {
    const example = await readFile(".env.example", "utf8");
    expect(example).toContain("WEBHOOKS_ENABLED=false");
    for (const key of [
      "WORKOS_PROVIDER_ENABLED=false",
      "IPINFO_PROVIDER_ENABLED=false",
      "LINEAR_PROVIDER_ENABLED=false",
      "UPSTASH_PUBSUB_ENABLED=false",
    ])
      expect(example).toContain(key);
  });
});

describe("optional secrets", () => {
  it("normalizes only empty secrets while disabled integrations remain mock-safe", () => {
    expect(
      readPhase2Config({
        WEBHOOKS_ENABLED: "false",
        ALERT_WEBHOOK_SECRET: "",
      }).alertWebhookSecret,
    ).toBeUndefined();
    expect(
      readPhase6Config({
        MOCK_DECISIONS_ENABLED: "false",
        MOCK_DECISION_SECRET: "",
      }).mockDecisionSecret,
    ).toBeUndefined();
    expect(
      readPhase7Config({ DASHBOARD_AUTH_ENABLED: "false", WORKOS_API_KEY: "" })
        .workosApiKey,
    ).toBeUndefined();
    expect(
      readPhase8Config({
        WORKOS_PROVIDER_ENABLED: "false",
        WORKOS_API_KEY: "",
      }).workos.apiKey,
    ).toBeUndefined();
  });

  it("rejects whitespace-padded secret material at every phase boundary", () => {
    expect(() =>
      readPhase2Config({
        ALERT_WEBHOOK_SECRET: ` ${"a".repeat(16)}`,
        WORKOS_WEBHOOK_SECRET: "b".repeat(16),
      }),
    ).toThrow("Invalid Phase 2 configuration.");
    expect(() =>
      readPhase6Config({
        MOCK_DECISIONS_ENABLED: "false",
        MOCK_DECISION_SECRET: `${"a".repeat(32)} `,
      }),
    ).toThrow("Invalid Phase 6 configuration.");
    expect(() =>
      readPhase7Config({
        DASHBOARD_AUTH_ENABLED: "false",
        DASHBOARD_CSRF_SECRET: ` ${"a".repeat(32)}`,
      }),
    ).toThrow("Invalid Phase 7 configuration.");
    expect(() =>
      readPhase8Config({
        WORKOS_PROVIDER_ENABLED: "false",
        WORKOS_API_KEY: `${"a".repeat(16)} `,
      }),
    ).toThrow("Invalid Phase 8 configuration.");
    expect(() =>
      readPhase8Config({
        IPINFO_PROVIDER_ENABLED: "false",
        GEOIP_CACHE_HMAC_KEY:
          " base64:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
      }),
    ).toThrow("Invalid Phase 8 configuration.");
  });

  it("fails early for short or missing secrets when a boundary is enabled", () => {
    expect(() =>
      readPhase2Config({
        WEBHOOKS_ENABLED: "true",
        ALERT_WEBHOOK_SECRET: "short",
        WORKOS_WEBHOOK_SECRET: "x".repeat(16),
      }),
    ).toThrow();
    expect(() =>
      readPhase2Config({
        WEBHOOKS_ENABLED: "true",
        ALERT_WEBHOOK_SECRET: " ",
        WORKOS_WEBHOOK_SECRET: " ".repeat(16),
      }),
    ).toThrow();
    expect(() =>
      readPhase7Config({
        DASHBOARD_AUTH_ENABLED: "true",
        WORKOS_API_KEY: " ",
        WORKOS_CLIENT_ID: "x".repeat(8),
        WORKOS_REDIRECT_URI: "https://example.test",
        WORKOS_COOKIE_PASSWORD: "x".repeat(32),
        DASHBOARD_CSRF_SECRET: "x".repeat(32),
      }),
    ).toThrow();
    expect(() =>
      readPhase8Config({
        DEMO_MODE: "staging",
        WEBHOOKS_ENABLED: "true",
        WORKOS_PROVIDER_ENABLED: "true",
        WORKOS_API_KEY: "short",
        WORKOS_WEBHOOK_SECRET: "x".repeat(16),
        WORKOS_STAGING_ORGANIZATION_ID: "org_123",
        WORKOS_STAGING_ALLOWED_USER_IDS: "user_123",
        WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "responder",
      }),
    ).toThrow();
  });
});
