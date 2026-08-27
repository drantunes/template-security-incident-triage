import { describe, expect, it } from "vitest";

import {
  normalizeDemoAlert,
  normalizeWorkOsMock,
} from "../../src/webhooks/normalizers.js";
import { makeDemoWebhook } from "../fixtures/phase2.js";

describe("webhook normalizers", () => {
  it("derives server-owned IDs and canonicalizes timestamp and IPv6", () => {
    const body = Buffer.from("fixture");
    const result = normalizeDemoAlert(
      makeDemoWebhook({
        occurredAt: "2026-08-27T08:59:00-03:00",
        ip: "2001:0db8:0:0:0:0:0:1",
      }),
      body,
      new Set(["demo"]),
    );
    expect(result.disposition).toBe("alert");
    if (result.disposition === "alert") {
      expect(result.alert).toMatchObject({
        occurredAt: "2026-08-27T11:59:00.000Z",
        ip: "2001:db8::1",
      });
      expect(result.alert.alertId).toMatch(/^alert_[a-f0-9]{64}$/u);
      expect(result.alert.idempotencyKey).toMatch(/^[a-f0-9]{64}$/u);
      expect(result.alert.rawPayloadRef).toMatch(/^sha256:[a-f0-9]{64}$/u);
    }
  });

  it("maps exactly the three documented synthetic WorkOS event kinds", () => {
    const fixtures = [
      [
        "mock.user.role_changed",
        {
          tenant_id: "tenant-1",
          subject_id: "subject-1",
          actor_id: "actor-1",
          previous_role: "member",
          new_role: "admin",
        },
        "unauthorized_privilege_change",
      ],
      [
        "mock.session.country_login",
        {
          tenant_id: "tenant-1",
          subject_id: "subject-1",
          actor_id: "actor-1",
          session_id: "session-1",
          ip: "203.0.113.10",
        },
        "disallowed_country_login",
      ],
      [
        "mock.session.unknown_device",
        {
          tenant_id: "tenant-1",
          subject_id: "subject-1",
          actor_id: "actor-1",
          session_id: "session-1",
          device_id: "device-1",
        },
        "unknown_device_login",
      ],
    ] as const;
    for (const [event, data, kind] of fixtures) {
      const result = normalizeWorkOsMock(
        {
          id: `event-${kind}`,
          event,
          created_at: "2026-08-27T12:00:00.000Z",
          data,
        },
        Buffer.from(event),
      );
      expect(result.disposition).toBe("alert");
      if (result.disposition === "alert") {
        expect(result.alert).toMatchObject({
          kind,
          actor: { id: "actor-1", type: "user" },
        });
      }
    }
  });

  it("dead-letters unknown and incompatible mock event names", () => {
    for (const [event, reasonCode] of [
      ["mock.unknown", "EVENT_UNKNOWN"],
      ["mock.v2.user.role_changed", "EVENT_VERSION_UNSUPPORTED"],
    ] as const) {
      expect(
        normalizeWorkOsMock(
          {
            id: "event-1",
            event,
            created_at: "2026-08-27T12:00:00.000Z",
            data: {},
          },
          Buffer.from(event),
        ),
      ).toMatchObject({ disposition: "dead_letter", reasonCode });
    }
  });
});
