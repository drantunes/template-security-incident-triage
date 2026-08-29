import { randomUUID } from "node:crypto";

import { LinearClient } from "@linear/sdk";
import { EventEmitterPubSub } from "@mastra/core/events";
import { RedisStreamsPubSub } from "@mastra/redis-streams";

import type { Phase8Config } from "../env.js";
import {
  createPhase8GeoIpProvider,
  createPhase8IdentityProvider,
} from "../providers/runtime-factory.js";
import { IpinfoLiteProvider } from "../providers/geoip-provider.js";
import { WorkOsIdentityProvider } from "../providers/identity-provider.js";
import { LinearIncidentProvider } from "../providers/linear-incident-provider.js";
import { normalizeWorkOsReal } from "../webhooks/normalizers.js";

export const phase8SmokeProviders = [
  "workos",
  "ipinfo",
  "linear",
  "upstash",
] as const;
export type Phase8SmokeProvider = (typeof phase8SmokeProviders)[number];

export type Phase8SmokeBoundaries = Readonly<{
  workos(
    input: Readonly<{ config: Phase8Config; signal: AbortSignal }>,
  ): Promise<void>;
  ipinfo(
    input: Readonly<{ config: Phase8Config; signal: AbortSignal }>,
  ): Promise<void>;
  linear(
    input: Readonly<{ config: Phase8Config; signal: AbortSignal }>,
  ): Promise<void>;
  upstash(
    input: Readonly<{ config: Phase8Config; signal: AbortSignal }>,
  ): Promise<void>;
}>;

export type Phase8SmokeResult = Readonly<{
  provider: Phase8SmokeProvider;
  mode: "mock" | "staging" | "production";
  enabled: true;
  cleanup: "not-requested" | "cleanup-safe";
  dryRun: boolean;
  network: "disabled" | "attempted";
  credentials: "redacted";
  validation: "implemented-not-validated-externally";
}>;

type UpstashSmokePubSub = Readonly<{
  subscribe(
    topic: string,
    callback: (
      event: unknown,
      ack?: () => Promise<void>,
      nack?: () => Promise<void>,
    ) => void | Promise<void>,
    options: Readonly<{ group: string; startFrom: "latest" }>,
  ): Promise<void>;
  publish(topic: string, event: unknown): Promise<void>;
  clearTopic(topic: string): Promise<void>;
  close(): Promise<void>;
}>;

/**
 * The only real-mode seam.  It deliberately keeps each provider operation
 * small: WorkOS/IPinfo/Linear are reads, while Upstash uses a unique stream
 * and removes it only after its delivery is terminally ACKed.
 */
export function createRealPhase8SmokeBoundaries(
  dependencies: Readonly<{
    createUpstashPubSub?: (config: Phase8Config) => UpstashSmokePubSub;
  }> = {},
): Phase8SmokeBoundaries {
  const createUpstashPubSub =
    dependencies.createUpstashPubSub ??
    ((config: Phase8Config): UpstashSmokePubSub =>
      new RedisStreamsPubSub({
        url: config.upstash.redisUrl!,
        redisOptions: {
          socket: { connectTimeout: 1_500, reconnectStrategy: false },
        },
        keyPrefix: config.upstash.keyPrefix,
        maxStreamLength: config.upstash.maxStreamLength,
        streamIdleTtlMs: config.upstash.streamIdleTtlMs,
        reclaimIntervalMs: config.upstash.reclaimIntervalMs,
        reclaimIdleMs: config.upstash.reclaimIdleMs,
        maxDeliveryAttempts: config.upstash.maxDeliveryAttempts,
      }));
  return {
    async workos({ config, signal }) {
      if (signal.aborted) throw new Error("WorkOS smoke was cancelled.");
      const provider = createPhase8IdentityProvider(config, () => false);
      const userId = [...config.workos.allowedUserIds][0];
      if (!provider || !config.workos.organizationId || !userId)
        throw new Error("WorkOS staging allowlist is incomplete.");
      await provider.getUser({
        tenantId: config.workos.organizationId,
        userId,
      });
      if (signal.aborted) throw new Error("WorkOS smoke was cancelled.");
    },
    async ipinfo({ config, signal }) {
      const provider = createPhase8GeoIpProvider(config);
      if (!provider)
        throw new Error("IPinfo staging configuration is incomplete.");
      // The complete HITL-8B fixture set: three public addresses plus one
      // bogon. No customer address or user-derived IP crosses this boundary.
      for (const ip of [
        "8.8.8.8",
        "31.251.149.240",
        "2001:1900:2100:280e::f0",
        "235.167.17.62",
      ] as const) {
        const result = await provider.lookup({
          ip,
          deadline: new Date(Date.now() + config.ipinfo.timeoutMs),
          signal,
        });
        const expectedBogon = ip === "235.167.17.62";
        if (
          (expectedBogon &&
            (result.outcome !== "unknown" || result.reasonCode !== "bogon")) ||
          (!expectedBogon && result.outcome !== "known")
        )
          throw new Error(
            "IPinfo smoke did not return the approved fixture outcome.",
          );
      }
    },
    async linear({ config, signal }) {
      if (signal.aborted) throw new Error("Linear smoke was cancelled.");
      if (
        !config.linear.apiKey ||
        !config.linear.workspaceId ||
        !config.linear.teamId
      )
        throw new Error("Linear staging destination is incomplete.");
      const client = new LinearClient({ apiKey: config.linear.apiKey });
      const [workspace, team, project] = await Promise.all([
        client.organization,
        client.team(config.linear.teamId),
        config.linear.projectId
          ? client.project(config.linear.projectId)
          : undefined,
      ]);
      const teamWorkspace = await team.organization;
      const projectTeams = project ? await project.teams() : undefined;
      if (
        workspace.id !== config.linear.workspaceId ||
        teamWorkspace.id !== config.linear.workspaceId ||
        (config.linear.projectId &&
          !projectTeams?.nodes?.some(
            (candidate) => candidate.id === config.linear.teamId,
          ))
      )
        throw new Error("Linear staging destination is not allowlisted.");
      if (signal.aborted) throw new Error("Linear smoke was cancelled.");
    },
    async upstash({ config, signal }) {
      if (signal.aborted) throw new Error("Upstash smoke was cancelled.");
      if (!config.upstash.redisUrl)
        throw new Error("Upstash staging configuration is incomplete.");
      const pubsub = createUpstashPubSub(config);
      const topic = `phase8-smoke-${randomUUID()}`;
      let received = false;
      let acknowledged = false;
      try {
        await pubsub.subscribe(
          topic,
          async (_event, ack) => {
            if (signal.aborted || !ack) return;
            // Recording receipt is the smoke effect. ACK is deliberately
            // after it so the pending entry remains recoverable on failure.
            received = true;
            if (signal.aborted) return;
            await ack();
            acknowledged = true;
          },
          { group: config.upstash.workflowConsumerGroup, startFrom: "latest" },
        );
        await pubsub.publish(topic, {
          type: "phase8.staging-smoke",
          runId: `phase8-smoke-${randomUUID()}`,
          data: { synthetic: true },
        });
        await waitForDelivery(() => acknowledged, signal, 3_000);
        if (!received || !acknowledged)
          throw new Error(
            "Upstash smoke did not reach an ACKed terminal delivery.",
          );
      } finally {
        // A UUID topic is eligible for cleanup only after this invocation has
        // observed and ACKed its terminal event. Aborts/deadlines intentionally
        // retain pending work rather than risking an unsafe clear.
        if (received && acknowledged && !signal.aborted)
          await pubsub.clearTopic(topic);
        await pubsub.close();
      }
    },
  };
}

/** Hermetic mirrors used by the default command mode and CI. */
export function createDryRunPhase8SmokeBoundaries(): Phase8SmokeBoundaries {
  return {
    async workos({ config, signal }) {
      if (signal.aborted) throw new Error("WorkOS dry-run was cancelled.");
      const userId = [...config.workos.allowedUserIds][0];
      if (!userId || !config.workos.organizationId)
        throw new Error("WorkOS staging allowlist is incomplete.");
      let membershipRole = "admin";
      const provider = new WorkOsIdentityProvider({
        // This dry-run is a complete synthetic lifecycle: read-only user and
        // session checks, then a guarded member→admin restore whose readback
        // becomes its own cleanup. It has no WorkOS client or credential.
        client: {
          userManagement: {
            getUser: async () => ({ id: userId }),
            listSessions: async () => ({ data: [] }),
            revokeSession: async () => ({}),
          },
          organizations: {
            getMembership: async () => ({
              id: "dry-membership",
              userId,
              organizationId: config.workos.organizationId,
              roleSlug: membershipRole,
              status: "active",
            }),
            updateMembership: async (_id, input) => {
              membershipRole = input.roleSlug;
              return {
                id: "dry-membership",
                userId,
                organizationId: config.workos.organizationId,
                roleSlug: membershipRole,
                status: "active",
              };
            },
          },
        },
        organizationId: config.workos.organizationId,
        allowedUserIds: config.workos.allowedUserIds,
        allowedRoleSlugs: config.workos.allowedRoleSlugs,
        authorizeMutation: ({ operation }) =>
          operation === "restore_previous_role",
      });
      await provider.getUser({
        tenantId: config.workos.organizationId,
        userId,
      });
      await provider.listSessions({
        tenantId: config.workos.organizationId,
        userId,
      });
      // Webhook normalization is a read-only boundary in the synthetic path;
      // signature bytes are independently covered at the HTTP route boundary.
      normalizeWorkOsReal(
        {
          id: "dry-webhook",
          event: "organization_membership.updated",
          created_at: "2026-08-29T00:00:00.000Z",
          data: {
            object: "organization_membership",
            id: "dry-membership",
            organization_id: config.workos.organizationId,
            user_id: userId,
            status: "active",
            created_at: "2026-08-29T00:00:00.000Z",
            updated_at: "2026-08-29T00:00:00.000Z",
            role: { slug: "admin" },
          },
        },
        new TextEncoder().encode("phase8-workos-dry-run"),
        {
          organizationId: config.workos.organizationId,
          userIds: config.workos.allowedUserIds,
          roleSlugs: config.workos.allowedRoleSlugs,
        },
      );
      await provider.restoreRole({
        tenantId: config.workos.organizationId,
        userId,
        membershipId: "dry-membership",
        expectedCurrentRole: "admin",
        previousRole: "member",
        approvalContext: {
          approvalId: "dry-approval",
          fenceToken: "dry-fence",
          deadline: "2030-08-29T00:00:00.000Z",
        },
        effect: {
          incidentId: "dry-incident",
          planId: "dry-plan",
          actionId: "dry-action",
          targetId: userId,
          idempotencyKey: "dry-restore",
        },
      });
    },
    async ipinfo({ config, signal }) {
      const provider = new IpinfoLiteProvider({
        token: config.ipinfo.token ?? "redacted",
        timeoutMs: config.ipinfo.timeoutMs,
        transport: async () => ({
          status: 200,
          json: async () => ({ country_code: "BR" }),
        }),
      });
      await provider.lookup({
        ip: "8.8.8.8",
        deadline: new Date(Date.now() + config.ipinfo.timeoutMs),
        signal,
      });
    },
    async linear({ config, signal }) {
      if (signal.aborted) throw new Error("Linear dry-run was cancelled.");
      if (
        !config.linear.workspaceId ||
        !config.linear.teamId ||
        !config.linear.severityLabelIds ||
        !config.linear.statusStateIds ||
        !config.linear.internalBaseUrl
      )
        throw new Error("Linear staging destination is incomplete.");
      const workspaceId = config.linear.workspaceId;
      const teamId = config.linear.teamId;
      const projectId = config.linear.projectId;
      const severityLabelIds = config.linear.severityLabelIds;
      const statusStateIds = config.linear.statusStateIds;
      const internalBaseUrl = config.linear.internalBaseUrl;
      let title = "";
      let stateId = statusStateIds.awaiting_approval;
      const provider = new LinearIncidentProvider({
        client: {
          createIssue: async (input) => {
            title = input.title;
            return { success: true, issueId: "dry_issue" };
          },
          updateIssue: async (_id, input) => {
            title = input.title;
            stateId = input.stateId ?? stateId;
            return { success: true, issueId: "dry_issue" };
          },
          searchIssues: async () => ({ nodes: [] }),
          issue: async (id) => ({
            id,
            title,
            state: { id: stateId },
            team: { id: teamId },
            ...(projectId ? { project: { id: projectId } } : {}),
          }),
        },
        workspaceId,
        teamId,
        ...(projectId ? { projectId } : {}),
        severityLabelIds,
        statusStateIds,
        internalBaseUrl,
        resolveDestination: async () => ({
          workspaceId,
          teamId,
          ...(projectId ? { projectId } : {}),
        }),
      });
      const created = await provider.create({
        idempotencyKey: "dry-run",
        generation: 1,
        projection: smokeProjection,
      });
      await provider.update({
        externalRef: created.externalRef,
        idempotencyKey: "dry-run",
        generation: 2,
        projection: { ...smokeProjection, status: "contained" },
      });
    },
    async upstash({ signal }) {
      if (signal.aborted) throw new Error("Upstash dry-run was cancelled.");
      const pubsub = new EventEmitterPubSub();
      let received = 0;
      await pubsub.subscribe("phase8-dry-run", async () => {
        received += 1;
      });
      await pubsub.publish("phase8-dry-run", {
        type: "phase8.staging-smoke",
        runId: "phase8-dry-run",
        data: { synthetic: true },
      });
      await pubsub.flush();
      await pubsub.close();
      if (received !== 1)
        throw new Error("Upstash dry-run boundary did not deliver.");
    },
  };
}

export async function runPhase8Smoke(
  input: Readonly<{
    provider: Phase8SmokeProvider;
    config: Phase8Config;
    real: boolean;
    cleanup: boolean;
    boundaries: Phase8SmokeBoundaries;
  }>,
): Promise<Phase8SmokeResult> {
  if (input.config.mode !== "staging" || !input.config[input.provider].enabled)
    throw new Error(`Staging flag for ${input.provider} is required.`);
  if (input.real && input.provider === "upstash" && !input.cleanup)
    throw new Error(
      "Upstash real mode requires --cleanup for the UUID-scoped cleanup.",
    );
  try {
    await withSmokeDeadline(
      (signal) =>
        input.boundaries[input.provider]({ config: input.config, signal }),
      input.provider,
    );
  } catch {
    // Do not let URLs, credentials, or broker details escape the staging
    // harness. The boundary has already received the abort on a deadline.
    throw new Error(
      `${input.provider} staging smoke failed; details redacted.`,
    );
  }
  return {
    provider: input.provider,
    mode: input.config.mode,
    enabled: true,
    cleanup:
      input.real && input.provider === "upstash"
        ? "cleanup-safe"
        : "not-requested",
    dryRun: !input.real,
    network: input.real ? "attempted" : "disabled",
    credentials: "redacted",
    validation: "implemented-not-validated-externally",
  };
}

const smokeProjection = {
  incidentId: "incident_1",
  tenantId: "tenant_1",
  kind: "unknown_device_login" as const,
  severity: "high" as const,
  status: "awaiting_approval" as const,
  occurredAt: "2026-08-29T00:00:00.000Z",
  summaryCode: "UNKNOWN_DEVICE_REQUIRES_REVIEW" as const,
  planHashVersion: 1 as const,
  planHash: "a".repeat(64),
  actionTypes: ["revoke_session" as const],
};

async function waitForDelivery(
  delivered: () => boolean,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!delivered() && Date.now() < deadline && !signal.aborted) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
}

async function withSmokeDeadline(
  operation: (signal: AbortSignal) => Promise<void>,
  provider: Phase8SmokeProvider,
): Promise<void> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      operation(controller.signal),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Error(`${provider} smoke exceeded its 3s bound.`));
        }, 3_000);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
