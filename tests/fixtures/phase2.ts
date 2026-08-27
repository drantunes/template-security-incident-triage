import { createHmac } from "node:crypto";

import type { Phase2Config } from "../../src/env.js";

export const phase2NowMs = Date.parse("2026-08-27T12:00:00.000Z");
export const phase2Timestamp = String(phase2NowMs);
export const alertSecret = "alert-secret-for-phase-two-tests";
export const workosSecret = "workos-secret-for-phase-two-tests";

export function makePhase2Config(
  overrides: Partial<Phase2Config> = {},
): Phase2Config {
  return {
    mode: "mock",
    webhooksEnabled: true,
    alertWebhookSecret: alertSecret,
    workosWebhookSecret: workosSecret,
    alertWebhookSources: new Set(["demo"]),
    webhookMaxBodyBytes: 65_536,
    mastraMaxBodyBytes: 1_048_576,
    outbox: {
      pollIntervalMs: 250,
      batchSize: 16,
      leaseMs: 10_000,
      maxAttempts: 5,
      backoffBaseMs: 500,
      backoffCapMs: 30_000,
      recoveryGraceMs: 10_000,
    },
    port: 3_000,
    ...overrides,
  };
}

export function signBody(
  body: string | Uint8Array,
  secret = alertSecret,
  timestamp = phase2Timestamp,
): string {
  const digest = createHmac("sha256", secret)
    .update(`${timestamp}.`, "utf8")
    .update(body)
    .digest("hex");
  return `t=${timestamp},v1=${digest}`;
}

export function makeDemoWebhook(
  overrides: Readonly<Record<string, unknown>> = {},
) {
  return {
    schemaVersion: 1,
    source: "demo",
    sourceEventId: "source-event-1",
    kind: "unauthorized_privilege_change",
    occurredAt: "2026-08-27T11:59:00.000Z",
    tenantId: "tenant-1",
    subjectId: "subject-1",
    actor: { id: "actor-1", type: "user" },
    target: { id: "subject-1", type: "user" },
    changes: { previousRole: "member", nextRole: "admin" },
    ...overrides,
  };
}
