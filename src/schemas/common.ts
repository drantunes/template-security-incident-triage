import { z } from "zod";

export const schemaVersion = z.literal(1);
export const opaqueId = z.string().trim().min(1).max(128);
export const shortText = z.string().trim().min(1).max(256);
export const longText = z.string().trim().min(1).max(4_096);
export const utcTimestamp = z.iso.datetime({
  offset: false,
  precision: 3,
});
export const sha256 = z.string().regex(/^[a-f0-9]{64}$/u);
export const evidenceReference = z
  .string()
  .regex(/^\[evidence:[^\]\s]{1,128}\]$/u);
export const runbookReference = z
  .string()
  .regex(/^\[runbook:[^\]@\s]{1,128}@[0-9]+\.[0-9]+\.[0-9]+\]$/u);
export const reference = z.union([evidenceReference, runbookReference]);

const jsonPrimitive = z.union([
  z.string().max(2_048),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);

export const boundedJsonObject = z
  .record(z.string().min(1).max(64), jsonPrimitive)
  .refine((value) => Object.keys(value).length <= 32, "too many keys");

export const actorSchema = z
  .object({
    id: opaqueId,
    type: z.enum(["user", "service", "system", "unknown"]),
    displayName: z.string().trim().min(1).max(128).optional(),
  })
  .strict();

export const targetSchema = z
  .object({
    id: opaqueId,
    type: z.enum(["user", "session", "device", "role", "resource"]),
  })
  .strict();
