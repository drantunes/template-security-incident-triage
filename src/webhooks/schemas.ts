import { z } from "zod";

import { boundedJsonObject } from "../schemas/common.js";
import { IncidentKindSchema } from "../schemas/incident.js";

const webhookId = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/u);
const webhookTimestamp = z.iso.datetime({ offset: true });
const actor = z
  .object({
    id: webhookId,
    type: z.enum(["user", "service", "system", "unknown"]),
    displayName: z.string().trim().min(1).max(128).optional(),
  })
  .strict();
const target = z
  .object({
    id: webhookId,
    type: z.enum(["user", "session", "device", "role", "resource"]),
  })
  .strict();

export const DemoAlertWebhookSchema = z
  .object({
    schemaVersion: z.literal(1),
    source: z.string().min(1).max(64),
    sourceEventId: webhookId,
    kind: IncidentKindSchema,
    occurredAt: webhookTimestamp,
    tenantId: webhookId,
    subjectId: webhookId,
    sessionId: webhookId.optional(),
    deviceId: webhookId.optional(),
    ip: z.ipv4().or(z.ipv6()).optional(),
    actor,
    target,
    changes: boundedJsonObject.optional(),
  })
  .strict();

export const WorkOsEnvelopeSchema = z
  .object({
    id: webhookId,
    event: z.string().min(1).max(128),
    created_at: webhookTimestamp,
    data: z.record(z.string(), z.unknown()),
  })
  .strict();

// Serialized WorkOS 8.13 webhook shapes put the entity directly in `data`.
// The entity's `object` is a discriminator string, not a nested record.
export const WorkOsRealEnvelopeSchema = z
  .object({
    id: webhookId,
    event: z.enum([
      "organization_membership.updated",
      "session.created",
      "session.revoked",
    ]),
    created_at: webhookTimestamp,
    data: z.record(z.string(), z.unknown()),
  })
  .strict();

export const WorkOsMembershipObjectSchema = z
  .object({
    object: z.literal("organization_membership"),
    id: webhookId,
    organization_id: webhookId,
    user_id: webhookId,
    role: z.object({ slug: z.string().trim().min(1).max(64) }).strict(),
    status: z.enum(["active", "inactive", "pending"]),
    created_at: webhookTimestamp,
    updated_at: webhookTimestamp,
  })
  .passthrough();

export const WorkOsSessionObjectSchema = z
  .object({
    object: z.literal("session"),
    id: webhookId,
    user_id: webhookId,
    organization_id: webhookId.optional(),
    status: z.enum(["active", "revoked", "expired"]),
    ip_address: z.ipv4().or(z.ipv6()).nullable(),
    created_at: webhookTimestamp,
    updated_at: webhookTimestamp,
  })
  .passthrough();

const commonWorkOsData = {
  tenant_id: webhookId,
  subject_id: webhookId,
  actor_id: webhookId,
} as const;

export const WorkOsRoleChangedDataSchema = z
  .object({
    ...commonWorkOsData,
    previous_role: z.string().trim().min(1).max(64),
    new_role: z.string().trim().min(1).max(64),
  })
  .strict();
export const WorkOsCountryLoginDataSchema = z
  .object({
    ...commonWorkOsData,
    session_id: webhookId,
    ip: z.ipv4().or(z.ipv6()),
  })
  .strict();
export const WorkOsUnknownDeviceDataSchema = z
  .object({
    ...commonWorkOsData,
    session_id: webhookId,
    device_id: webhookId,
    ip: z.ipv4().or(z.ipv6()).optional(),
  })
  .strict();

export type DemoAlertWebhook = z.infer<typeof DemoAlertWebhookSchema>;
