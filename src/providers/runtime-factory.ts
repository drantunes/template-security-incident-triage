import { WorkOS } from "@workos-inc/node";

import type { Phase8Config } from "../env.js";
import type { OperationalStore } from "../db/operational-store.js";
import { DomainError } from "../domain/errors.js";
import type { IncidentProvider } from "./incident-provider.js";
import { createLinearIncidentProvider } from "./linear-incident-provider.js";
import { MockIncidentProvider } from "./mock-incident-provider.js";
import {
  WorkOsIdentityProvider,
  type IdentityMutationAuthorizer,
  type WorkOsIdentityClient,
} from "./identity-provider.js";
import { IpinfoLiteProvider, type GeoIpTransport } from "./geoip-provider.js";

/**
 * Selects adapters exactly once from the validated mode.  A staging process
 * is never permitted to quietly replace an enabled real adapter with a mock.
 * Test callers may provide fake transports/clients without changing this
 * selection logic.
 */
export function createPhase8IncidentProvider(
  config: Phase8Config,
  dependencies: Readonly<{ store?: OperationalStore }> = {},
): IncidentProvider {
  if (config.mode === "mock") return new MockIncidentProvider(dependencies);
  if (!config.linear.enabled) {
    return new DisabledIncidentProvider();
  }
  if (
    !config.linear.apiKey ||
    !config.linear.workspaceId ||
    !config.linear.teamId ||
    !config.linear.severityLabelIds ||
    !config.linear.statusStateIds ||
    !config.linear.internalBaseUrl
  )
    throw new DomainError("VALIDATION_FAILED");
  return createLinearIncidentProvider({
    apiKey: config.linear.apiKey,
    workspaceId: config.linear.workspaceId,
    teamId: config.linear.teamId,
    ...(config.linear.projectId ? { projectId: config.linear.projectId } : {}),
    severityLabelIds: config.linear.severityLabelIds,
    statusStateIds: config.linear.statusStateIds,
    internalBaseUrl: config.linear.internalBaseUrl,
  });
}

class DisabledIncidentProvider implements IncidentProvider {
  readonly providerId = "disabled" as const;
  async create(): Promise<never> {
    throw new DomainError("VALIDATION_FAILED");
  }
  async update(): Promise<never> {
    throw new DomainError("VALIDATION_FAILED");
  }
}

export function createPhase8IdentityProvider(
  config: Phase8Config,
  authorizeMutation: IdentityMutationAuthorizer,
  dependencies: Readonly<{ openStore?: () => OperationalStore }> = {},
): WorkOsIdentityProvider | undefined {
  if (!config.workos.enabled) return undefined;
  if (!config.workos.apiKey || !config.workos.organizationId)
    throw new DomainError("VALIDATION_FAILED");
  const workos = new WorkOS(config.workos.apiKey);
  const client: WorkOsIdentityClient = {
    userManagement: {
      getUser: (userId) => workos.userManagement.getUser(userId),
      listSessions: async ({ userId }) =>
        workos.userManagement.listSessions(userId),
      revokeSession: async (sessionId) => {
        await workos.userManagement.revokeSession({ sessionId });
        return { id: sessionId, status: "revoked" };
      },
    },
    organizations: {
      getMembership: (membershipId) =>
        workos.userManagement.getOrganizationMembership(membershipId),
      updateMembership: (membershipId, input) =>
        workos.userManagement.updateOrganizationMembership(membershipId, input),
    },
  };
  return new WorkOsIdentityProvider({
    client,
    organizationId: config.workos.organizationId,
    allowedUserIds: config.workos.allowedUserIds,
    allowedRoleSlugs: config.workos.allowedRoleSlugs,
    authorizeMutation,
    ...(dependencies.openStore ? { openStore: dependencies.openStore } : {}),
    timeoutMs: 1_500,
  });
}

export function createPhase8GeoIpProvider(
  config: Phase8Config,
  dependencies: Readonly<{
    store?: OperationalStore;
    openStore?: () => OperationalStore;
    transport?: GeoIpTransport;
  }> = {},
): IpinfoLiteProvider | undefined {
  if (!config.ipinfo.enabled) return undefined;
  if (!config.ipinfo.token || !config.ipinfo.cacheHmacKey)
    throw new DomainError("VALIDATION_FAILED");
  return new IpinfoLiteProvider({
    token: config.ipinfo.token,
    timeoutMs: config.ipinfo.timeoutMs,
    cacheTtlMs: config.ipinfo.cacheTtlSeconds * 1_000,
    retentionDays: config.ipinfo.evidenceRetentionDays,
    cacheHmacKey: config.ipinfo.cacheHmacKey,
    cacheHmacKeyVersion: config.ipinfo.cacheHmacKeyVersion!,
    ...(config.ipinfo.previousCacheHmacKey
      ? {
          previousCacheHmacKey: config.ipinfo.previousCacheHmacKey,
          previousCacheHmacKeyVersion:
            config.ipinfo.previousCacheHmacKeyVersion!,
        }
      : {}),
    ...(dependencies.store ? { store: dependencies.store } : {}),
    ...(dependencies.openStore ? { openStore: dependencies.openStore } : {}),
    ...(dependencies.transport ? { transport: dependencies.transport } : {}),
  });
}
