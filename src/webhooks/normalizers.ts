import { createHash } from "node:crypto";

import { AlertSchema, type Alert } from "../schemas/alert.js";
import {
  DemoAlertWebhookSchema,
  WorkOsCountryLoginDataSchema,
  WorkOsEnvelopeSchema,
  WorkOsRoleChangedDataSchema,
  WorkOsUnknownDeviceDataSchema,
  type DemoAlertWebhook,
} from "./schemas.js";

export type NormalizationResult =
  | Readonly<{ disposition: "alert"; alert: Alert }>
  | Readonly<{
      disposition: "dead_letter";
      reasonCode: "EVENT_UNKNOWN" | "EVENT_VERSION_UNSUPPORTED";
      eventRef: string;
    }>;

export function normalizeDemoAlert(
  value: unknown,
  rawBody: Uint8Array,
  allowedSources: ReadonlySet<string>,
): NormalizationResult {
  const input = DemoAlertWebhookSchema.parse(value);
  if (!allowedSources.has(input.source)) {
    throw new Error("ALERT_SOURCE_UNSUPPORTED");
  }
  return {
    disposition: "alert",
    alert: buildAlert(input, rawBody),
  };
}

export function normalizeWorkOsMock(
  value: unknown,
  rawBody: Uint8Array,
): NormalizationResult {
  const envelope = WorkOsEnvelopeSchema.parse(value);
  if (envelope.event.startsWith("mock.v2.")) {
    return deadLetter("EVENT_VERSION_UNSUPPORTED", rawBody);
  }
  const common = {
    schemaVersion: 1 as const,
    source: "workos-mock",
    sourceEventId: envelope.id,
    occurredAt: envelope.created_at,
  };
  switch (envelope.event) {
    case "mock.user.role_changed": {
      const data = WorkOsRoleChangedDataSchema.parse(envelope.data);
      return {
        disposition: "alert",
        alert: buildAlert(
          {
            ...common,
            kind: "unauthorized_privilege_change",
            tenantId: data.tenant_id,
            subjectId: data.subject_id,
            actor: { id: data.actor_id, type: "user" },
            target: { id: data.subject_id, type: "user" },
            changes: {
              previousRole: data.previous_role,
              nextRole: data.new_role,
            },
          },
          rawBody,
        ),
      };
    }
    case "mock.session.country_login": {
      const data = WorkOsCountryLoginDataSchema.parse(envelope.data);
      return {
        disposition: "alert",
        alert: buildAlert(
          {
            ...common,
            kind: "disallowed_country_login",
            tenantId: data.tenant_id,
            subjectId: data.subject_id,
            sessionId: data.session_id,
            ip: data.ip,
            actor: { id: data.actor_id, type: "user" },
            target: { id: data.session_id, type: "session" },
          },
          rawBody,
        ),
      };
    }
    case "mock.session.unknown_device": {
      const data = WorkOsUnknownDeviceDataSchema.parse(envelope.data);
      return {
        disposition: "alert",
        alert: buildAlert(
          {
            ...common,
            kind: "unknown_device_login",
            tenantId: data.tenant_id,
            subjectId: data.subject_id,
            sessionId: data.session_id,
            deviceId: data.device_id,
            ...(data.ip ? { ip: data.ip } : {}),
            actor: { id: data.actor_id, type: "user" },
            target: { id: data.device_id, type: "device" },
          },
          rawBody,
        ),
      };
    }
    default:
      return deadLetter("EVENT_UNKNOWN", rawBody);
  }
}

function buildAlert(input: DemoAlertWebhook, rawBody: Uint8Array): Alert {
  const identityHash = createHash("sha256")
    .update(input.source, "utf8")
    .update(Buffer.from([0]))
    .update(input.sourceEventId, "utf8")
    .digest("hex");
  const rawHash = createHash("sha256").update(rawBody).digest("hex");
  return AlertSchema.parse({
    ...input,
    occurredAt: new Date(input.occurredAt).toISOString(),
    ...(input.ip ? { ip: canonicalizeIp(input.ip) } : {}),
    alertId: `alert_${identityHash}`,
    rawPayloadRef: `sha256:${rawHash}`,
    idempotencyKey: identityHash,
  });
}

function canonicalizeIp(ip: string): string {
  if (!ip.includes(":")) return ip;
  return new URL(`http://[${ip}]/`).hostname.slice(1, -1);
}

function deadLetter(
  reasonCode: "EVENT_UNKNOWN" | "EVENT_VERSION_UNSUPPORTED",
  rawBody: Uint8Array,
): NormalizationResult {
  return {
    disposition: "dead_letter",
    reasonCode,
    eventRef: `sha256:${createHash("sha256").update(rawBody).digest("hex")}`,
  };
}
