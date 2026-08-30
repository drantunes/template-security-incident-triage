import { createHash } from "node:crypto";

import type { DemoScenario } from "./contracts.js";
import { signDemoDevice } from "./evidence-baseline.js";

const scenarioDetails = {
  privilege: {
    kind: "unauthorized_privilege_change",
    runbook: "RB-IDENTITY-001",
    severity: "high",
    actions: ["restore_previous_role", "revoke_session"],
  },
  country: {
    kind: "disallowed_country_login",
    runbook: "RB-IDENTITY-002",
    severity: "high",
    actions: ["revoke_session", "require_reauthentication"],
  },
  device: {
    kind: "unknown_device_login",
    runbook: "RB-IDENTITY-003",
    severity: "medium",
    actions: ["revoke_session", "mark_device_for_review"],
  },
} as const;

export const DEMO_OCCURRED_AT = "2026-08-29T12:00:00.000Z";

export function demoId(namespace: string, value: string): string {
  return `${namespace}_${createHash("sha256").update(`${namespace}\0${value}`).digest("hex").slice(0, 24)}`;
}

export function fixtureForScenario(scenario: DemoScenario, demoRunId: string) {
  const subjectId = demoId("subject", demoRunId);
  const sessionId = demoId("session", demoRunId);
  const deviceId = demoId("device", demoRunId);
  const base = {
    schemaVersion: 1 as const,
    source: "demo",
    sourceEventId: demoId("event", demoRunId),
    occurredAt: DEMO_OCCURRED_AT,
    tenantId: demoId("tenant", demoRunId),
    subjectId,
    actor: { id: demoId("actor", demoRunId), type: "user" as const },
  };
  switch (scenario) {
    case "privilege":
      return {
        ...base,
        kind: scenarioDetails.privilege.kind,
        sessionId,
        target: { id: subjectId, type: "user" as const },
        // The public event requests the v2 local-authority lookup; the seed
        // writes the matching ledger row before this event is accepted.
        changes: {
          contextVersion: 2,
          previousRole: "member",
          nextRole: "admin",
          approved: false,
        },
      };
    case "country":
      return {
        ...base,
        kind: scenarioDetails.country.kind,
        sessionId,
        ip: "198.51.100.8",
        target: { id: sessionId, type: "session" as const },
        changes: {
          allowedCountry: "US",
          observedCountry: "CA",
          geoip: "fixture-v1",
        },
      };
    case "device": {
      // This is the credential presented by the signed alert. The F9 fake
      // binds its persisted authority back to this exact value.
      const deviceAuthority = signDemoDevice({
        tenantId: base.tenantId,
        subjectId,
        deviceId,
        expiresAt: "2026-08-30T12:00:00.000Z",
        nonce: demoId("device-nonce", base.sourceEventId),
      });
      return {
        ...base,
        kind: scenarioDetails.device.kind,
        sessionId,
        deviceId,
        target: { id: deviceId, type: "device" as const },
        changes: {
          signature: JSON.stringify(deviceAuthority),
          authorized: false,
        },
      };
    }
  }
}

export function scenarioDetailsFor(scenario: DemoScenario) {
  return scenarioDetails[scenario];
}
