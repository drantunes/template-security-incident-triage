import { describe, expect, it } from "vitest";

import {
  SignatureError,
  verifyWebhookSignature,
} from "../../src/webhooks/signature.js";
import {
  alertSecret,
  phase2NowMs,
  phase2Timestamp,
  signBody,
} from "../fixtures/phase2.js";

describe("WorkOS-compatible webhook signature", () => {
  const body = Buffer.from('{"value":"raw bytes"}', "utf8");

  it("validates exact raw bytes and accepts rotated v1 candidates", () => {
    const valid = signBody(body);
    expect(() =>
      verifyWebhookSignature({
        header: `t=${phase2Timestamp},v1=${"0".repeat(64)},${valid.split(",")[1]}`,
        secret: alertSecret,
        rawBody: body,
        nowMs: phase2NowMs,
      }),
    ).not.toThrow();
    expect(() =>
      verifyWebhookSignature({
        header: `${valid},v1=${"f".repeat(64)}`,
        secret: alertSecret,
        rawBody: body,
        nowMs: phase2NowMs,
      }),
    ).not.toThrow();
  });

  it("rejects altered bytes and malformed members", () => {
    expect(() =>
      verifyWebhookSignature({
        header: signBody(body),
        secret: alertSecret,
        rawBody: Buffer.from('{ "value":"raw bytes"}', "utf8"),
        nowMs: phase2NowMs,
      }),
    ).toThrowError(SignatureError);
    for (const header of [
      undefined,
      `t=${phase2Timestamp}`,
      `t=${phase2Timestamp},t=${phase2Timestamp},v1=${"a".repeat(64)}`,
      `t=${phase2Timestamp},v1=xyz`,
      `t=${phase2Timestamp},v2=${"a".repeat(64)}`,
    ]) {
      expect(() =>
        verifyWebhookSignature({
          header,
          secret: alertSecret,
          rawBody: body,
          nowMs: phase2NowMs,
        }),
      ).toThrowError(SignatureError);
    }
  });

  it("rejects past and future timestamps outside the absolute window", () => {
    for (const timestamp of [
      String(phase2NowMs - 300_001),
      String(phase2NowMs + 300_001),
    ]) {
      expect(() =>
        verifyWebhookSignature({
          header: signBody(body, alertSecret, timestamp),
          secret: alertSecret,
          rawBody: body,
          nowMs: phase2NowMs,
        }),
      ).toThrowError(expect.objectContaining({ code: "SIGNATURE_EXPIRED" }));
    }
  });

  it("uses all current/previous secrets and the approved WorkOS 180s window", () => {
    const previous = "previous-workos-secret";
    const timestamp = String(phase2NowMs - 180_000);
    expect(() =>
      verifyWebhookSignature({
        header: signBody(body, previous, timestamp),
        secrets: [alertSecret, previous],
        rawBody: body,
        nowMs: phase2NowMs,
        toleranceMs: 180_000,
      }),
    ).not.toThrow();
    expect(() =>
      verifyWebhookSignature({
        header: signBody(body, previous, String(phase2NowMs - 180_001)),
        secrets: [alertSecret, previous],
        rawBody: body,
        nowMs: phase2NowMs,
        toleranceMs: 180_000,
      }),
    ).toThrowError(expect.objectContaining({ code: "SIGNATURE_EXPIRED" }));
  });
});
