import { afterEach, describe, expect, it, vi } from "vitest";
import { RequestContext } from "@mastra/core/request-context";

import type { EvidenceProviderInput } from "../../src/evidence/contracts.js";

import {
  createEvidenceReadTool,
  runProviderInspection,
} from "../../src/mastra/tools/evidence-read-tool.js";
import { MockCloudEvidenceProvider } from "../../src/providers/cloud-evidence-provider.js";
import { MockEndpointEvidenceProvider } from "../../src/providers/endpoint-evidence-provider.js";
import { MockIdentityEvidenceProvider } from "../../src/providers/identity-evidence-provider.js";

afterEach(() => vi.useRealTimers());

const request = {
  tenantId: "tenant-1",
  incidentId: "incident-1",
  subjectId: "subject-1",
  workflowRunId: "run-1",
  incidentKind: "unauthorized_privilege_change" as const,
  occurredAt: "2026-08-27T12:00:00.000Z",
};

describe("Phase 4 read-only provider contracts", () => {
  it.each([
    [new MockIdentityEvidenceProvider(), "mock-identity"],
    [new MockEndpointEvidenceProvider(), "mock-endpoint"],
    [new MockCloudEvidenceProvider(), "mock-cloud"],
  ])(
    "returns strict deterministic synthetic facts",
    async (provider, providerName) => {
      const first = await provider.inspect(request, {
        signal: new AbortController().signal,
        attempt: 1,
      });
      const second = await provider.inspect(request, {
        signal: new AbortController().signal,
        attempt: 1,
      });
      expect(first).toEqual(second);
      expect(first).toMatchObject({
        status: "success",
        provider: providerName,
      });
      expect(provider.calls).toHaveLength(2);
      expect(JSON.stringify(first)).not.toContain("ignore prior");
    },
  );

  it("retries only explicit retryable failures once", async () => {
    const provider = new MockCloudEvidenceProvider({
      behavior: "rate_limited",
    });
    const output = await runProviderInspection({
      source: "cloud",
      provider,
      request,
      toolCallId: "tool-call-1",
      timeoutMs: 1_000,
    });
    expect(provider.calls.map((call) => call.attempt)).toEqual([1, 2]);
    expect(output.result).toMatchObject({
      status: "rate_limited",
      error: { code: "RATE_LIMITED", attempt: 2 },
    });
    const invalid = new MockCloudEvidenceProvider({
      behavior: "invalid_response",
    });
    await runProviderInspection({
      source: "cloud",
      provider: invalid,
      request,
      toolCallId: "tool-call-2",
      timeoutMs: 1_000,
    });
    expect(invalid.calls).toHaveLength(1);
  });

  it.each([
    ["timeout", "TIMEOUT"],
    ["not_found", "NOT_FOUND"],
    ["invalid_response", "INVALID_RESPONSE"],
    ["aborted", "ABORTED"],
  ] as const)(
    "ignores adapter retry claims for the local non-retryable %s policy",
    async (status, code) => {
      let calls = 0;
      const provider = {
        source: "cloud" as const,
        providerId: "policy-adversary",
        inspect: async () => {
          calls += 1;
          return {
            status,
            provider: "policy-adversary",
            error: {
              code,
              retryable: true,
              safeRef: "provider:policy-adversary:forged-retry",
              attempt: 1,
            },
          };
        },
      };
      const output = await runProviderInspection({
        source: "cloud",
        provider,
        request,
        toolCallId: `tool-call-${status}`,
        timeoutMs: 1_000,
      });
      expect(calls).toBe(1);
      expect(output.result).toMatchObject({
        status: "invalid_response",
        error: { code: "INVALID_RESPONSE", retryable: false },
      });
    },
  );

  it("does not retry a coherent provider timeout", async () => {
    const provider = new MockEndpointEvidenceProvider({ behavior: "timeout" });
    const output = await runProviderInspection({
      source: "endpoint",
      provider,
      request,
      toolCallId: "tool-call-timeout-policy",
      timeoutMs: 1_000,
    });
    expect(provider.calls).toHaveLength(1);
    expect(output.result).toMatchObject({
      status: "timeout",
      error: { code: "TIMEOUT", retryable: false },
    });
  });

  it("derives the reported attempt and safe reference from the actual call", async () => {
    let calls = 0;
    const provider = {
      source: "cloud" as const,
      providerId: "attempt-adversary",
      inspect: async () => {
        calls += 1;
        const actualAttempt = calls as 1 | 2;
        return {
          status: actualAttempt === 1 ? "rate_limited" : "unavailable",
          provider: "attempt-adversary",
          error: {
            code: actualAttempt === 1 ? "RATE_LIMITED" : "UNAVAILABLE",
            retryable: true,
            safeRef: "provider:attempt-adversary:forged",
            attempt: actualAttempt === 1 ? 2 : 1,
          },
        };
      },
    };
    const output = await runProviderInspection({
      source: "cloud",
      provider,
      request,
      toolCallId: "tool-call-attempt-policy",
      timeoutMs: 1_000,
    });
    expect(calls).toBe(2);
    expect(output.result).toMatchObject({
      status: "unavailable",
      error: {
        attempt: 2,
        safeRef: "provider:attempt-adversary:attempt-2",
      },
    });
  });

  it("does not retry an operational timeout exception", async () => {
    let calls = 0;
    const provider = {
      source: "endpoint" as const,
      providerId: "timeout-adapter",
      inspect: async () => {
        calls += 1;
        throw Object.assign(new Error("deadline exceeded"), {
          name: "TimeoutError",
          code: "TIMEOUT",
        });
      },
    };
    const output = await runProviderInspection({
      source: "endpoint",
      provider,
      request,
      toolCallId: "tool-call-thrown-timeout",
      timeoutMs: 1_000,
    });
    expect(calls).toBe(1);
    expect(output.result).toMatchObject({
      status: "timeout",
      error: { code: "TIMEOUT", retryable: false },
    });
  });

  it("propagates abort without exposing an arbitrary interface", async () => {
    const controller = new AbortController();
    controller.abort();
    const provider = new MockEndpointEvidenceProvider();
    const output = await runProviderInspection({
      source: "endpoint",
      provider,
      request,
      toolCallId: "tool-call-3",
      timeoutMs: 1_000,
      parentSignal: controller.signal,
    });
    expect(output.result).toMatchObject({ error: { code: "ABORTED" } });
    expect(output).not.toHaveProperty("url");
    expect(output).not.toHaveProperty("query");
  });

  it("rejects unknown fields and trusted-scope mismatches before the adapter", async () => {
    const provider = new MockIdentityEvidenceProvider();
    const tool = createEvidenceReadTool({
      id: "identity-read-tool",
      source: "identity",
      description: "test",
      provider,
      timeoutMs: 1_000,
    });
    expect(
      tool.inputSchema?.["~standard"].validate({
        ...request,
        url: "https://invalid",
      }),
    ).toMatchObject({
      issues: expect.any(Array),
    });
    const requestContext = new RequestContext<EvidenceProviderInput>([
      ["tenantId", "other-tenant"],
      ["incidentId", request.incidentId],
      ["subjectId", request.subjectId],
      ["workflowRunId", request.workflowRunId],
      ["incidentKind", request.incidentKind],
      ["occurredAt", request.occurredAt],
    ]);
    await expect(
      tool.execute?.(request, {
        requestContext,
        observe: {
          span: async (_name, fn) => fn(),
          log: () => {},
        },
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(provider.calls).toHaveLength(0);
  });

  it.each([
    ["identity" as const, new MockIdentityEvidenceProvider()],
    ["endpoint" as const, new MockEndpointEvidenceProvider()],
    ["cloud" as const, new MockCloudEvidenceProvider()],
  ])(
    "rejects every model-controlled selector mismatch for %s",
    async (source, provider) => {
      const trusted = {
        ...request,
        sessionId: "session-trusted",
        deviceId: "device-known-1",
        ip: "198.51.100.8",
      };
      const tool = createEvidenceReadTool({
        id: `${source}-read-tool`,
        source,
        description: "test",
        provider,
        timeoutMs: 1_000,
      });
      const requestContext = new RequestContext<EvidenceProviderInput>([
        ["tenantId", trusted.tenantId],
        ["incidentId", trusted.incidentId],
        ["subjectId", trusted.subjectId],
        ["workflowRunId", trusted.workflowRunId],
        ["incidentKind", trusted.incidentKind],
        ["occurredAt", trusted.occurredAt],
        ["sessionId", trusted.sessionId],
        ["deviceId", trusted.deviceId],
        ["ip", trusted.ip],
      ]);
      const mismatches = [
        { ...trusted, incidentKind: "unknown_device_login" as const },
        { ...trusted, occurredAt: "2026-08-27T12:00:01.000Z" },
        { ...trusted, sessionId: "session-attacker" },
        { ...trusted, deviceId: "device-attacker" },
        { ...trusted, ip: "203.0.113.9" },
      ];
      for (const mismatch of mismatches) {
        await expect(
          tool.execute?.(mismatch, {
            requestContext,
            observe: {
              span: async (_name, fn) => fn(),
              log: () => {},
            },
          }),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      expect(provider.calls).toHaveLength(0);
    },
  );

  it("enforces the deadline when a provider ignores AbortSignal", async () => {
    vi.useFakeTimers();
    let release!: (value: unknown) => void;
    const provider = {
      source: "cloud" as const,
      providerId: "mock-cloud",
      inspect: () =>
        new Promise<unknown>((resolve) => {
          release = resolve;
        }),
    };
    const completion = runProviderInspection({
      source: "cloud",
      provider,
      request,
      toolCallId: "tool-call-deadline",
      timeoutMs: 10,
    });
    await vi.advanceTimersByTimeAsync(10);
    await expect(completion).resolves.toMatchObject({
      result: { status: "timeout", error: { code: "TIMEOUT" } },
    });
    release({ status: "success", provider: "mock-cloud", facts: [] });
    await vi.runAllTimersAsync();
  });

  it("turns a truly malformed provider response into a typed partial failure", async () => {
    const provider = {
      source: "cloud" as const,
      providerId: "mock-cloud",
      inspect: async () => ({
        status: "success",
        provider: "mock-cloud",
        facts: [
          {
            semanticKey: "bad-time",
            observedAt: "bad-time",
            factType: "login.country",
            value: "US",
            confidence: 1,
            confidenceProvenance: "provider",
            rawPayloadRef: "protected:test:bad-time",
            sensitivity: "internal",
            incomplete: false,
          },
        ],
      }),
    };
    await expect(
      runProviderInspection({
        source: "cloud",
        provider,
        request,
        toolCallId: "tool-call-invalid",
        timeoutMs: 1_000,
      }),
    ).resolves.toMatchObject({
      result: {
        status: "invalid_response",
        error: { code: "INVALID_RESPONSE", retryable: false },
      },
    });
  });

  it("supports real adapter identities while rejecting a wrong domain", async () => {
    const workos = {
      source: "identity" as const,
      providerId: "workos",
      inspect: async () => ({
        status: "success",
        provider: "workos",
        facts: [
          {
            semanticKey: "subject",
            observedAt: request.occurredAt,
            factType: "identity.subject",
            value: request.subjectId,
            confidence: 1,
            confidenceProvenance: "provider",
            rawPayloadRef: "protected:workos:subject",
            sensitivity: "confidential",
            incomplete: false,
          },
        ],
      }),
    };
    await expect(
      runProviderInspection({
        source: "identity",
        provider: workos,
        request,
        toolCallId: "tool-call-workos",
        timeoutMs: 1_000,
      }),
    ).resolves.toMatchObject({ result: { provider: "workos" } });
    await expect(
      runProviderInspection({
        source: "cloud",
        provider: workos,
        request,
        toolCallId: "tool-call-wrong-domain",
        timeoutMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });
});
