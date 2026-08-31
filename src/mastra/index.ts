import { Mastra } from "@mastra/core/mastra";
import { MastraAuthWorkos } from "@mastra/auth-workos";
import { RedisStreamsPubSub } from "@mastra/redis-streams";

import { smokeAgent } from "./agents/smoke-agent.js";
import { identityInvestigator } from "./agents/identity-investigator.js";
import { endpointInvestigator } from "./agents/endpoint-investigator.js";
import { cloudInvestigator } from "./agents/cloud-investigator.js";
import { correlationAnalyst } from "./agents/correlation-analyst.js";
import { socSupervisor } from "./agents/soc-supervisor.js";
import { responsePlanner } from "./agents/response-planner.js";
import { storage } from "./storage.js";
import { baselineWorkflow } from "./workflows/baseline-workflow.js";
import { createIncidentIngestionWorkflow } from "./workflows/incident-ingestion-workflow.js";
import { observability } from "./observability.js";
import { phase10MastraScorers } from "./evals/mastra-scorers.js";
import {
  assertPhase8ControlPlaneAuth,
  hasRealPhase8Provider,
  readPhase8Config,
} from "../env.js";
import {
  createPhase8GeoIpProvider,
  createPhase8IdentityProvider,
  createPhase8IncidentProvider,
} from "../providers/runtime-factory.js";
import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import {
  persistRedisClaimDeleted,
  persistRedisDecodeFailure,
} from "../db/redis-decode-failure-operations.js";
import {
  DisabledIdentityEvidenceProvider,
  MockIdentityEvidenceProvider,
  WorkOsIdentityEvidenceProvider,
} from "../providers/identity-evidence-provider.js";
import { GeoIpIdentityEvidenceProvider } from "../providers/geoip-evidence-provider.js";

const phase8Config = readPhase8Config();
assertPhase8ControlPlaneAuth(phase8Config);
// Do not couple the runtime API to DASHBOARD_AUTH_ENABLED: with a real
// provider, Mastra's own server auth is mandatory even if the dashboard UI is
// intentionally not exposed.
const runtimeAuth =
  hasRealPhase8Provider(phase8Config) &&
  process.env.WORKOS_API_KEY &&
  process.env.WORKOS_CLIENT_ID &&
  process.env.WORKOS_COOKIE_PASSWORD
    ? new MastraAuthWorkos({
        apiKey: process.env.WORKOS_API_KEY,
        clientId: process.env.WORKOS_CLIENT_ID,
        redirectUri: process.env.WORKOS_REDIRECT_URI,
        session: { cookiePassword: process.env.WORKOS_COOKIE_PASSWORD },
      })
    : undefined;

export { storage } from "./storage.js";
const phase8IncidentProvider = createPhase8IncidentProvider(phase8Config);
const phase8GeoIpProvider = createPhase8GeoIpProvider(phase8Config, {
  openStore: createLibSqlOperationalStore,
});
const phase8IdentityProvider = createPhase8IdentityProvider(
  phase8Config,
  // The adapter independently verifies the active F6 fence and the durable
  // target-bound provider ledger before a remote mutation.
  () => true,
  { openStore: createLibSqlOperationalStore },
);
const phase8IdentityEvidenceBase =
  phase8Config.mode === "mock"
    ? new MockIdentityEvidenceProvider()
    : phase8IdentityProvider
      ? new WorkOsIdentityEvidenceProvider(phase8IdentityProvider)
      : new DisabledIdentityEvidenceProvider();
const phase8IdentityEvidenceProvider = phase8GeoIpProvider
  ? new GeoIpIdentityEvidenceProvider({
      base: phase8IdentityEvidenceBase,
      geoip: phase8GeoIpProvider,
      timeoutMs: phase8Config.ipinfo.timeoutMs,
    })
  : phase8IdentityEvidenceBase;
const phase8IncidentIngestionWorkflow = createIncidentIngestionWorkflow(
  createLibSqlOperationalStore,
  {},
  { identityProvider: phase8IdentityEvidenceProvider },
  {},
  {
    enabled: true,
    provider: phase8IncidentProvider,
    mode: phase8Config.mode,
    ...(phase8IdentityProvider
      ? { identityProvider: phase8IdentityProvider }
      : {}),
  },
);
// The official adapter is constructed once and handed directly to Mastra. It is
// deliberately absent in mock mode; no staging configuration may silently use
// the in-memory PubSub fallback.
const stagingPubSub = phase8Config.upstash.enabled
  ? new RedisStreamsPubSub({
      url: phase8Config.upstash.redisUrl,
      keyPrefix: phase8Config.upstash.keyPrefix,
      maxStreamLength: phase8Config.upstash.maxStreamLength,
      streamIdleTtlMs: phase8Config.upstash.streamIdleTtlMs,
      reclaimIntervalMs: phase8Config.upstash.reclaimIntervalMs,
      reclaimIdleMs: phase8Config.upstash.reclaimIdleMs,
      maxDeliveryAttempts: phase8Config.upstash.maxDeliveryAttempts,
      onDecodeFailure: async (failure) => {
        const store = createLibSqlOperationalStore();
        try {
          await persistRedisDecodeFailure(store, failure);
        } finally {
          store.close();
        }
      },
      onClaimDeleted: async (failure) => {
        const store = createLibSqlOperationalStore();
        try {
          await persistRedisClaimDeleted(store, failure);
        } finally {
          store.close();
        }
      },
    })
  : undefined;

export const mastra = new Mastra({
  scorers: phase10MastraScorers,
  agents: {
    smokeAgent,
    identityInvestigator,
    endpointInvestigator,
    cloudInvestigator,
    correlationAnalyst,
    socSupervisor,
    responsePlanner,
  },
  workflows: {
    baselineWorkflow,
    incidentIngestionWorkflow: phase8IncidentIngestionWorkflow,
  },
  storage,
  observability,
  ...(stagingPubSub ? { pubsub: stagingPubSub } : {}),
  ...(runtimeAuth ? { server: { auth: runtimeAuth } } : {}),
});
