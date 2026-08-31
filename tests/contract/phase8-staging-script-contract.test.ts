import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";

import { readPhase8Config } from "../../src/env.js";
import {
  createRealPhase8SmokeBoundaries,
  runPhase8Smoke,
  type Phase8SmokeBoundaries,
  type Phase8SmokeProvider,
} from "../../src/staging/phase8-smoke.js";

const exec = promisify(execFile);
const script = "scripts/phase8-staging-harness.mts";
const states = JSON.stringify({
  received: "r",
  investigating: "i",
  awaiting_approval: "aa",
  approved: "a",
  rejected: "rej",
  containing: "c",
  contained: "co",
  failed: "f",
  closed: "cl",
});

function environment(provider: string): NodeJS.ProcessEnv {
  const base = {
    ...process.env,
    DEMO_MODE: "staging",
    PHASE8_STAGING_CONFIRM: "PHASE8_HERMETIC_CHECK",
  };
  if (provider === "workos")
    return {
      ...base,
      WORKOS_PROVIDER_ENABLED: "true",
      WEBHOOKS_ENABLED: "true",
      WORKOS_API_KEY: "fake-workos-api-key",
      WORKOS_WEBHOOK_SECRET: "fake-workos-webhook-secret",
      WORKOS_STAGING_ORGANIZATION_ID: "tenant_1",
      WORKOS_STAGING_ALLOWED_USER_IDS: "user_1",
      WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "member,admin",
    };
  if (provider === "ipinfo")
    return {
      ...base,
      IPINFO_PROVIDER_ENABLED: "true",
      IPINFO_TOKEN: "fake-ipinfo-token",
      GEOIP_CACHE_HMAC_KEY:
        "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      GEOIP_CACHE_HMAC_KEY_VERSION: "hmac-sha256-v1",
    };
  if (provider === "linear")
    return {
      ...base,
      LINEAR_PROVIDER_ENABLED: "true",
      LINEAR_API_KEY: "fake-linear-api-key",
      LINEAR_WORKSPACE_ID: "workspace_1",
      LINEAR_TEAM_ID: "team_1",
      LINEAR_SEVERITY_LABEL_IDS_JSON: JSON.stringify({
        low: "l",
        medium: "m",
        high: "h",
        critical: "c",
      }),
      LINEAR_STATUS_STATE_IDS_JSON: states,
      LINEAR_INTERNAL_BASE_URL: "https://incidents.example.test",
    };
  return {
    ...base,
    UPSTASH_PUBSUB_ENABLED: "true",
    UPSTASH_REDIS_URL: "rediss://token@upstash.example.test:6379",
  };
}

describe("Phase 8 staging script contract", () => {
  it.each(["workos", "ipinfo", "linear", "upstash"])(
    "runs %s dry-run with fakes and redacted zero-network output",
    async (provider) => {
      const result = await exec(
        process.execPath,
        ["--import", "tsx", script, provider],
        { cwd: process.cwd(), env: environment(provider) },
      );
      expect(JSON.parse(result.stdout)).toMatchObject({
        provider,
        dryRun: true,
        network: "disabled",
        credentials: "redacted",
      });
      expect(result.stdout).not.toContain("fake-workos-api-key");
    },
  );
  it.each(["workos", "ipinfo", "linear", "upstash"])(
    "is default-deny and refuses %s real mode without its separate confirmation",
    async (provider) => {
      await expect(
        exec(
          process.execPath,
          ["--import", "tsx", script, provider, "--real"],
          {
            cwd: process.cwd(),
            env: environment(provider),
          },
        ),
      ).rejects.toMatchObject({
        stderr: expect.stringContaining("PHASE8_REAL_CONFIRM"),
      });
    },
  );

  it("refuses a command with no staging confirmation", async () => {
    await expect(
      exec(process.execPath, ["--import", "tsx", script, "ipinfo"], {
        cwd: process.cwd(),
        env: { ...process.env },
      }),
    ).rejects.toBeDefined();
  });

  it.each(["workos", "ipinfo", "linear", "upstash"] as const)(
    "calls exactly the authorized %s boundary in real mode without a network double",
    async (provider) => {
      const calls: Phase8SmokeProvider[] = [];
      const boundaries: Phase8SmokeBoundaries = {
        workos: async () => void calls.push("workos"),
        ipinfo: async () => void calls.push("ipinfo"),
        linear: async () => void calls.push("linear"),
        upstash: async () => void calls.push("upstash"),
      };
      const result = await runPhase8Smoke({
        provider,
        config: readPhase8Config(environment(provider)),
        real: true,
        cleanup: provider === "upstash",
        boundaries,
      });
      expect(calls).toEqual([provider]);
      expect(result).toMatchObject({
        provider,
        dryRun: false,
        network: "attempted",
        credentials: "redacted",
        validation: "implemented-not-validated-externally",
      });
    },
  );

  it("requires cleanup confirmation for the only write-capable real smoke", async () => {
    const boundaries: Phase8SmokeBoundaries = {
      workos: async () => undefined,
      ipinfo: async () => undefined,
      linear: async () => undefined,
      upstash: async () => undefined,
    };
    await expect(
      runPhase8Smoke({
        provider: "upstash",
        config: readPhase8Config(environment("upstash")),
        real: true,
        cleanup: false,
        boundaries,
      }),
    ).rejects.toThrow("requires --cleanup");
  });

  it("ACKs the Upstash smoke after receipt and before UUID-topic cleanup", async () => {
    const calls: string[] = [];
    let callback:
      | ((
          event: unknown,
          ack?: () => Promise<void>,
          nack?: () => Promise<void>,
        ) => void | Promise<void>)
      | undefined;
    const boundaries = createRealPhase8SmokeBoundaries({
      createUpstashPubSub: () => ({
        subscribe: async (_topic, listener) => {
          calls.push("subscribe");
          callback = listener;
        },
        publish: async () => {
          calls.push("publish");
          await callback?.(
            {},
            async () => void calls.push("ack"),
            async () => void calls.push("nack"),
          );
        },
        clearTopic: async () => void calls.push("clear"),
        close: async () => void calls.push("close"),
      }),
    });

    await boundaries.upstash({
      config: readPhase8Config(environment("upstash")),
      signal: new AbortController().signal,
    });
    expect(calls).toEqual(["subscribe", "publish", "ack", "clear", "close"]);
  });

  it("never clears a pending Upstash topic after cancellation", async () => {
    const calls: string[] = [];
    let resolveAck!: () => void;
    const pendingAck = new Promise<void>((resolve) => {
      resolveAck = resolve;
    });
    let callback:
      | ((
          event: unknown,
          ack?: () => Promise<void>,
          nack?: () => Promise<void>,
        ) => void | Promise<void>)
      | undefined;
    const boundaries = createRealPhase8SmokeBoundaries({
      createUpstashPubSub: () => ({
        subscribe: async (_topic, listener) => {
          calls.push("subscribe");
          callback = listener;
        },
        publish: async () => {
          calls.push("publish");
          void callback?.(
            {},
            async () => pendingAck,
            async () => undefined,
          );
        },
        clearTopic: async () => void calls.push("clear"),
        close: async () => void calls.push("close"),
      }),
    });
    const controller = new AbortController();
    const run = boundaries.upstash({
      config: readPhase8Config(environment("upstash")),
      signal: controller.signal,
    });
    await Promise.resolve();
    controller.abort();
    await expect(run).rejects.toThrow(
      "did not reach an ACKed terminal delivery",
    );
    expect(calls).toEqual(["subscribe", "publish", "close"]);
    resolveAck();
  });

  it("redacts a timed-out pending Upstash smoke and skips cleanup", async () => {
    vi.useFakeTimers();
    const calls: string[] = [];
    try {
      const boundaries = createRealPhase8SmokeBoundaries({
        createUpstashPubSub: () => ({
          subscribe: async () => void calls.push("subscribe"),
          publish: async () => void calls.push("publish"),
          clearTopic: async () => void calls.push("clear"),
          close: async () => void calls.push("close"),
        }),
      });
      const run = runPhase8Smoke({
        provider: "upstash",
        config: readPhase8Config(environment("upstash")),
        real: true,
        cleanup: true,
        boundaries,
      });
      const rejection = expect(run).rejects.toThrow(
        "upstash staging smoke failed; details redacted.",
      );
      await vi.advanceTimersByTimeAsync(3_000);
      await rejection;
      await vi.advanceTimersByTimeAsync(25);
      expect(calls).toEqual(["subscribe", "publish", "close"]);
    } finally {
      vi.useRealTimers();
    }
  });
});
