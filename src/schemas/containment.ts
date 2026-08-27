import { z } from "zod";

import {
  boundedJsonObject,
  longText,
  opaqueId,
  schemaVersion,
  sha256,
  utcTimestamp,
} from "./common.js";

export const ContainmentActionTypeSchema = z.enum([
  "revoke_session",
  "restore_previous_role",
  "mark_device_for_review",
  "require_reauthentication",
]);

export const ContainmentActionSchema = z
  .object({
    actionId: opaqueId,
    type: ContainmentActionTypeSchema,
    targetId: opaqueId,
    input: boundedJsonObject,
    impact: longText,
    preconditions: z.array(longText).min(1).max(16),
    rollback: longText,
    verification: longText,
  })
  .strict();

export const ContainmentPlanSchema = z
  .object({
    schemaVersion,
    planId: opaqueId,
    incidentId: opaqueId,
    tenantId: opaqueId,
    planVersion: z.number().int().positive(),
    planHashVersion: z.number().int().positive(),
    planHash: sha256,
    createdAt: utcTimestamp,
    expiresAt: utcTimestamp,
    actions: z.array(ContainmentActionSchema).min(1).max(16),
  })
  .strict()
  .refine((plan) => plan.expiresAt > plan.createdAt, {
    message: "expiresAt must be after createdAt",
    path: ["expiresAt"],
  });

export type ContainmentActionType = z.infer<typeof ContainmentActionTypeSchema>;
export type ContainmentAction = z.infer<typeof ContainmentActionSchema>;
export type ContainmentPlan = z.infer<typeof ContainmentPlanSchema>;
