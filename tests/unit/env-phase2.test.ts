import { describe, expect, it } from "vitest";

import { readPhase2Config } from "../../src/env.js";

describe("Phase 2 configuration", () => {
  it("fails early without mock webhook secrets", () => {
    expect(() => readPhase2Config({})).toThrow(/required/u);
  });

  it("validates bounded local defaults and source allowlist", () => {
    const config = readPhase2Config({
      PATH: "/usr/bin",
      ALERT_WEBHOOK_SECRET: "a".repeat(16),
      WORKOS_WEBHOOK_SECRET: "b".repeat(16),
      ALERT_WEBHOOK_SOURCES: "demo,second-source, INVALID SOURCE ",
    });
    expect(config).toMatchObject({
      mode: "mock",
      webhookMaxBodyBytes: 65_536,
      mastraMaxBodyBytes: 1_048_576,
      outbox: { batchSize: 16, maxAttempts: 5 },
    });
    expect([...config.alertWebhookSources]).toEqual(["demo", "second-source"]);
  });

  it("accepts staging without enabling providers and rejects unbounded values", () => {
    const base = {
      ALERT_WEBHOOK_SECRET: "a".repeat(16),
      WORKOS_WEBHOOK_SECRET: "b".repeat(16),
    };
    expect(readPhase2Config({ ...base, DEMO_MODE: "staging" }).mode).toBe(
      "staging",
    );
    expect(() =>
      readPhase2Config({ ...base, WEBHOOK_MAX_BODY_BYTES: "999999" }),
    ).toThrow(/Invalid/u);
  });
});
