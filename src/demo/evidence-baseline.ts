import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

import type { OperationalStore } from "../db/operational-store.js";
import type { EvidenceProviderInput } from "../evidence/contracts.js";

const deviceSignatureSecret = "phase9-demo-device-signature-v1";

export type DeviceSignatureBaseline = Readonly<{
  tenantId: string;
  subjectId: string;
  deviceId: string;
  expiresAt: string;
  nonce: string;
  signature: string;
}>;

export type DemoEvidenceBaseline = Readonly<{
  version: 1;
  identity?: Readonly<{
    actorId: string;
    previousRole: string;
    currentRole: string;
    approved: boolean;
  }>;
  cloud?: Readonly<{
    allowedCountry: "US" | "CA";
    abnormalHistory: boolean;
    countryByIp: Readonly<Record<string, "US" | "CA">>;
  }>;
  device?: DeviceSignatureBaseline;
}>;

const DeviceBaselineSchema = z
  .object({
    tenantId: z.string().min(1),
    subjectId: z.string().min(1),
    deviceId: z.string().min(1),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(1),
    signature: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .strict();
const DemoEvidenceBaselineSchema = z
  .object({
    version: z.literal(1),
    identity: z
      .object({
        actorId: z.string().min(1),
        previousRole: z.string().min(1),
        currentRole: z.string().min(1),
        approved: z.boolean(),
      })
      .strict()
      .optional(),
    cloud: z
      .object({
        allowedCountry: z.enum(["US", "CA"]),
        abnormalHistory: z.boolean(),
        countryByIp: z.record(z.string(), z.enum(["US", "CA"])),
      })
      .strict()
      .optional(),
    device: DeviceBaselineSchema.optional(),
  })
  .strict();

export function signDemoDevice(
  input: Omit<DeviceSignatureBaseline, "signature">,
): DeviceSignatureBaseline {
  return {
    ...input,
    signature: createHmac("sha256", deviceSignatureSecret)
      .update(deviceSignatureMessage(input))
      .digest("hex"),
  };
}

export function verifyDemoDevice(
  device: DeviceSignatureBaseline | undefined,
  input: EvidenceProviderInput,
  usedNonces: Set<string>,
): boolean {
  if (!device || !input.deviceId || usedNonces.has(device.nonce)) return false;
  if (
    device.tenantId !== input.tenantId ||
    device.subjectId !== input.subjectId ||
    device.deviceId !== input.deviceId ||
    Date.parse(device.expiresAt) <= Date.parse(input.occurredAt)
  )
    return false;
  const expected = Buffer.from(
    createHmac("sha256", deviceSignatureSecret)
      .update(deviceSignatureMessage(device))
      .digest("hex"),
    "hex",
  );
  const presented = Buffer.from(device.signature, "hex");
  if (
    presented.length !== expected.length ||
    !timingSafeEqual(presented, expected)
  )
    return false;
  usedNonces.add(device.nonce);
  return true;
}

export async function readDemoEvidenceBaseline(
  openStore: (() => OperationalStore) | undefined,
  input: EvidenceProviderInput,
): Promise<DemoEvidenceBaseline | undefined> {
  if (!openStore) return undefined;
  const store = openStore();
  try {
    const result = await store.execute({
      sql: `SELECT snapshot_json, integrity_hash, schema_version,
          (SELECT canonical_json FROM alerts
            WHERE tenant_id = ? AND incident_id = ? ORDER BY occurred_at DESC LIMIT 1) AS alert_json
        FROM identity_snapshots
        WHERE tenant_id = ? AND subject_id = ? AND incident_id = ?
        ORDER BY captured_at DESC LIMIT 1`,
      args: [
        input.tenantId,
        input.incidentId,
        input.tenantId,
        input.subjectId,
        input.incidentId,
      ],
    });
    const row = result.rows[0];
    const value = row?.snapshot_json;
    const integrityHash = row?.integrity_hash;
    if (
      typeof value !== "string" ||
      typeof integrityHash !== "string" ||
      row?.schema_version !== 1
    )
      return undefined;
    const parsed = DemoEvidenceBaselineSchema.safeParse(JSON.parse(value));
    if (
      !parsed.success ||
      !safeEqualHex(integrityHash, baselineIntegrityHash(parsed.data))
    )
      return undefined;
    if (!baselineMatchesPresentedAlert(parsed.data, row?.alert_json))
      return undefined;
    return parsed.data;
  } catch {
    return undefined;
  } finally {
    store.close();
  }
}

/** Consume a signed-device nonce through a shared, durable LibSQL ledger. */
export async function consumeDemoDeviceNonce(
  openStore: (() => OperationalStore) | undefined,
  device: DeviceSignatureBaseline,
  input: EvidenceProviderInput,
): Promise<boolean> {
  if (!openStore) return false;
  const store = openStore();
  try {
    const nonceKey = createHash("sha256")
      .update(
        [
          "phase9-device-nonce-v1",
          device.tenantId,
          device.subjectId,
          device.deviceId,
          device.expiresAt,
          device.nonce,
        ].join("\0"),
      )
      .digest("hex");
    const result = await store.execute({
      sql: `INSERT OR IGNORE INTO consumer_effect_ledger(
        consumer_group, event_id, status, attempt_count, fence_token,
        lease_expires_at, completed_at
      ) VALUES ('phase9-device-nonce', ?, 'completed', 1, ?, ?, ?)`,
      args: [nonceKey, nonceKey, device.expiresAt, input.occurredAt],
    });
    return result.rowsAffected === 1;
  } finally {
    store.close();
  }
}

export async function isDemoDeviceAuthorized(
  openStore: (() => OperationalStore) | undefined,
  input: EvidenceProviderInput,
): Promise<boolean> {
  if (!openStore || !input.deviceId) return false;
  const store = openStore();
  try {
    const result = await store.execute({
      sql: `SELECT 1 FROM authorized_devices
        WHERE tenant_id = ? AND subject_id = ? AND device_id = ?
          AND authorized_at <= ? AND (revoked_at IS NULL OR revoked_at > ?)
        LIMIT 1`,
      args: [
        input.tenantId,
        input.subjectId,
        input.deviceId,
        input.occurredAt,
        input.occurredAt,
      ],
    });
    return result.rows.length === 1;
  } finally {
    store.close();
  }
}

export function baselineIntegrityHash(baseline: DemoEvidenceBaseline): string {
  return createHash("sha256").update(canonicalJson(baseline)).digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right))
    return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function deviceSignatureMessage(
  input: Omit<DeviceSignatureBaseline, "signature">,
): string {
  return [
    input.tenantId,
    input.subjectId,
    input.deviceId,
    input.expiresAt,
    input.nonce,
  ].join("\0");
}

function baselineMatchesPresentedAlert(
  baseline: DemoEvidenceBaseline,
  alertJson: unknown,
): boolean {
  if (!baseline.device) return true;
  if (typeof alertJson !== "string") return false;
  try {
    const alert = JSON.parse(alertJson) as {
      changes?: { signature?: unknown };
    };
    if (typeof alert.changes?.signature !== "string") return false;
    const presented = DeviceBaselineSchema.parse(
      JSON.parse(alert.changes.signature),
    );
    return canonicalJson(presented) === canonicalJson(baseline.device);
  } catch {
    return false;
  }
}
