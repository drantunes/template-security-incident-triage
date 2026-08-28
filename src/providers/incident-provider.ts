import { z } from "zod";

import { opaqueId, sha256, utcTimestamp } from "../schemas/common.js";
import { ContainmentActionTypeSchema } from "../schemas/containment.js";
import {
  IncidentSeveritySchema,
  IncidentStatusSchema,
} from "../schemas/incident.js";

export const ExternalIncidentProjectionSchema = z
  .object({
    incidentId: opaqueId,
    tenantId: opaqueId,
    kind: z.enum([
      "unauthorized_privilege_change",
      "disallowed_country_login",
      "unknown_device_login",
    ]),
    severity: IncidentSeveritySchema,
    status: IncidentStatusSchema,
    occurredAt: utcTimestamp,
    summaryCode: z.enum([
      "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
      "COUNTRY_LOGIN_REQUIRES_REVIEW",
      "UNKNOWN_DEVICE_REQUIRES_REVIEW",
      "CONTAINMENT_REJECTED",
      "CONTAINMENT_SUCCEEDED",
      "CONTAINMENT_FAILED",
    ]),
    planHashVersion: z.literal(1),
    planHash: sha256,
    actionTypes: z.array(ContainmentActionTypeSchema).min(1).max(2),
  })
  .strict();

export type ExternalIncidentProjection = z.infer<
  typeof ExternalIncidentProjectionSchema
>;

export const ExternalIncidentResultSchema = z
  .object({
    externalRef: z.string().regex(/^mock-incident-[a-f0-9]{16}$/u),
  })
  .strict();

export type ExternalIncidentResult = z.infer<
  typeof ExternalIncidentResultSchema
>;

export class ExternalIncidentSupersededError extends Error {}

export interface IncidentProvider {
  create(input: {
    projection: ExternalIncidentProjection;
    idempotencyKey: string;
    generation: number;
  }): Promise<ExternalIncidentResult>;
  update(input: {
    externalRef: string;
    projection: ExternalIncidentProjection;
    idempotencyKey: string;
    generation: number;
  }): Promise<ExternalIncidentResult>;
}
