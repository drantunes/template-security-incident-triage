import { describe, expect, it } from "vitest";

import {
  signDemoDevice,
  verifyDemoDevice,
} from "../../src/demo/evidence-baseline.js";
import { MockEndpointEvidenceProvider } from "../../src/providers/endpoint-evidence-provider.js";

const input = {
  tenantId: "tenant-phase9",
  incidentId: "incident-phase9",
  subjectId: "subject-phase9",
  workflowRunId: "run-phase9",
  incidentKind: "unknown_device_login" as const,
  occurredAt: "2026-08-29T12:00:00.000Z",
  deviceId: "device-phase9",
};

function signed() {
  return signDemoDevice({
    tenantId: input.tenantId,
    subjectId: input.subjectId,
    deviceId: input.deviceId,
    expiresAt: "2026-08-30T12:00:00.000Z",
    nonce: "nonce-phase9-device",
  });
}

describe("F9 device signature boundary", () => {
  it("rejects missing, tampered, expired, replayed and cross-principal authority", () => {
    expect(verifyDemoDevice(undefined, input, new Set())).toBe(false);
    expect(
      verifyDemoDevice(
        { ...signed(), signature: "00".repeat(32) },
        input,
        new Set(),
      ),
    ).toBe(false);
    expect(
      verifyDemoDevice(
        { ...signed(), expiresAt: "2026-08-28T12:00:00.000Z" },
        input,
        new Set(),
      ),
    ).toBe(false);
    const used = new Set<string>();
    expect(verifyDemoDevice(signed(), input, used)).toBe(true);
    expect(verifyDemoDevice(signed(), input, used)).toBe(false);
    expect(
      verifyDemoDevice(
        signed(),
        { ...input, tenantId: "tenant-other" },
        new Set(),
      ),
    ).toBe(false);
    expect(
      verifyDemoDevice(
        signed(),
        { ...input, subjectId: "subject-other" },
        new Set(),
      ),
    ).toBe(false);
  });

  it("fails closed in the default provider and accepts only an explicit authority", async () => {
    const inspect = (provider: MockEndpointEvidenceProvider) =>
      provider.inspect(input, {
        signal: new AbortController().signal,
        attempt: 1,
      });
    const defaultResult = await inspect(new MockEndpointEvidenceProvider());
    expect(defaultResult.status).toBe("success");
    if (defaultResult.status === "success") {
      expect(
        defaultResult.facts.find(
          (fact) => fact.factType === "device.signatureValid",
        )?.value,
      ).toBe(false);
    }
    const explicitResult = await inspect(
      new MockEndpointEvidenceProvider({
        verifyDeviceSignature: (candidate) =>
          candidate.tenantId === input.tenantId &&
          candidate.subjectId === input.subjectId &&
          candidate.deviceId === input.deviceId,
      }),
    );
    expect(explicitResult.status).toBe("success");
    if (explicitResult.status === "success") {
      expect(
        explicitResult.facts.find(
          (fact) => fact.factType === "device.signatureValid",
        )?.value,
      ).toBe(true);
    }
  });
});
