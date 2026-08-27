import { createHmac, timingSafeEqual } from "node:crypto";

export const WEBHOOK_TOLERANCE_MS = 300_000;

export type SignatureFailureCode =
  | "SIGNATURE_MISSING"
  | "SIGNATURE_MALFORMED"
  | "SIGNATURE_INVALID"
  | "SIGNATURE_EXPIRED";

export class SignatureError extends Error {
  constructor(readonly code: SignatureFailureCode) {
    super("Webhook signature validation failed.");
    this.name = "SignatureError";
  }
}

export function verifyWebhookSignature(
  input: Readonly<{
    header: string | undefined;
    secret: string;
    rawBody: Uint8Array;
    nowMs?: number;
  }>,
): void {
  if (!input.header) throw new SignatureError("SIGNATURE_MISSING");
  const parsed = parseSignatureHeader(input.header);
  const nowMs = input.nowMs ?? Date.now();
  if (Math.abs(nowMs - parsed.timestampMs) > WEBHOOK_TOLERANCE_MS) {
    throw new SignatureError("SIGNATURE_EXPIRED");
  }
  const prefix = Buffer.from(`${parsed.timestamp}.`, "utf8");
  const expected = createHmac("sha256", input.secret)
    .update(prefix)
    .update(input.rawBody)
    .digest();
  let matched = 0;
  for (const candidate of parsed.signatures) {
    matched |= Number(timingSafeEqual(expected, candidate));
  }
  if (matched === 0) throw new SignatureError("SIGNATURE_INVALID");
}

function parseSignatureHeader(header: string): Readonly<{
  timestamp: string;
  timestampMs: number;
  signatures: readonly Buffer[];
}> {
  let timestamp: string | undefined;
  const signatures: Buffer[] = [];
  for (const member of header.split(",")) {
    const separator = member.indexOf("=");
    if (separator <= 0 || separator === member.length - 1) {
      throw new SignatureError("SIGNATURE_MALFORMED");
    }
    const key = member.slice(0, separator);
    const value = member.slice(separator + 1);
    if (key === "t") {
      if (timestamp || !/^[0-9]{13}$/u.test(value)) {
        throw new SignatureError("SIGNATURE_MALFORMED");
      }
      timestamp = value;
    } else if (key === "v1") {
      if (!/^[a-fA-F0-9]{64}$/u.test(value)) {
        throw new SignatureError("SIGNATURE_MALFORMED");
      }
      signatures.push(Buffer.from(value, "hex"));
    } else {
      throw new SignatureError("SIGNATURE_MALFORMED");
    }
  }
  if (!timestamp || signatures.length === 0) {
    throw new SignatureError("SIGNATURE_MALFORMED");
  }
  const timestampMs = Number(timestamp);
  if (!Number.isSafeInteger(timestampMs)) {
    throw new SignatureError("SIGNATURE_MALFORMED");
  }
  return { timestamp, timestampMs, signatures };
}
