import { z } from "zod";

import {
  longText,
  opaqueId,
  schemaVersion,
  sha256,
  utcTimestamp,
} from "./common.js";

const approvalBase = {
  schemaVersion,
  approvalId: opaqueId,
  planId: opaqueId,
  incidentId: opaqueId,
  tenantId: opaqueId,
  planHashVersion: z.number().int().positive(),
  planHash: sha256,
};

export const ApprovalRequestSchema = z
  .object({
    ...approvalBase,
    requestedAt: utcTimestamp,
    expiresAt: utcTimestamp,
    status: z.literal("pending"),
  })
  .strict()
  .refine((request) => request.expiresAt > request.requestedAt, {
    message: "expiresAt must be after requestedAt",
    path: ["expiresAt"],
  });

export const ApprovalDecisionSchema = z.discriminatedUnion("decision", [
  z
    .object({
      ...approvalBase,
      decision: z.literal("approved"),
      decidedBy: opaqueId,
      decidedByRole: z.literal("soc_manager"),
      decidedAt: utcTimestamp,
      reason: longText.optional(),
    })
    .strict(),
  z
    .object({
      ...approvalBase,
      decision: z.literal("rejected"),
      decidedBy: opaqueId,
      decidedByRole: z.literal("soc_manager"),
      decidedAt: utcTimestamp,
      reason: longText,
    })
    .strict(),
]);

export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;
export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;
