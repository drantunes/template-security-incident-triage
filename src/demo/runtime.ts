import { resolve } from "node:path";

import { Mastra } from "@mastra/core/mastra";
import { MastraCompositeStore } from "@mastra/core/storage";
import { LibSQLStore } from "@mastra/libsql";

import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { createIncidentIngestionWorkflow } from "../mastra/workflows/incident-ingestion-workflow.js";
import { MockCloudEvidenceProvider } from "../providers/cloud-evidence-provider.js";
import { MockEndpointEvidenceProvider } from "../providers/endpoint-evidence-provider.js";
import { MockIdentityEvidenceProvider } from "../providers/identity-evidence-provider.js";
import { MockIncidentProvider } from "../providers/mock-incident-provider.js";
import { DeterministicRunbookEmbedder } from "../runbooks/embeddings.js";
import { retrieveRunbook } from "../runbooks/retrieve.js";
import { LibSqlRunbookVectorStore } from "../runbooks/vector-store.js";
import { deterministicResponsePlanner } from "../triage/prompt-safe-decision.js";
import { fixedClock } from "../domain/clock.js";
import type { MockContainmentState } from "../containment/mock-state.js";
import type { Phase2Config, Phase6Config } from "../env.js";
import { demoId, fixtureForScenario } from "./fixtures.js";
import type { DemoScenario } from "./contracts.js";
import {
  createPhase4Observability,
  installPhase4Observability,
} from "../mastra/observability.js";
import { phase10MastraScorers } from "../mastra/evals/mastra-scorers.js";

export const webhookSecret = "phase9-demo-webhook-secret-not-for-production";
export const decisionSecret = "phase9-demo-decision-secret-not-for-production";
export const resumeSecret = "phase9-demo-resume-secret-not-for-production";
// B1's declared manifest clock is the sole clock for this deterministic demo.
// Fixture timestamps and operational writes are intentionally anchored here;
// no report or evaluation outcome may depend on wall time.
export const fixedNow = "2026-08-30T00:00:00.000Z";

export function phase2Config(): Phase2Config {
  return {
    mode: "mock",
    webhooksEnabled: true,
    alertWebhookSecret: webhookSecret,
    workosWebhookSecret: webhookSecret,
    alertWebhookSources: new Set(["demo"]),
    webhookMaxBodyBytes: 65_536,
    mastraMaxBodyBytes: 1_048_576,
    outbox: {
      pollIntervalMs: 250,
      batchSize: 16,
      leaseMs: 10_000,
      maxAttempts: 5,
      backoffBaseMs: 500,
      backoffCapMs: 30_000,
      recoveryGraceMs: 10_000,
    },
    port: 3_000,
  };
}

export function phase6Config(): Phase6Config {
  return {
    mode: "mock",
    mockDecisionsEnabled: true,
    mockDecisionSecret: decisionSecret,
    approvalResumeSecret: resumeSecret,
    actionTimeoutMs: 1_000,
    rateLimit: 8,
  };
}

export function mockState(
  scenario: DemoScenario,
  demoRunId: string,
): MockContainmentState {
  const fixture = fixtureForScenario(scenario, demoRunId);
  const deviceId = "deviceId" in fixture ? fixture.deviceId : undefined;
  return {
    sessions: new Map(fixture.sessionId ? [[fixture.sessionId, "active"]] : []),
    roles: new Map([[fixture.subjectId, "admin"]]),
    devices: new Map(deviceId ? [[deviceId, "clear"]] : []),
    reauthentication: new Map(),
    calls: new Map(),
  };
}

export function createDemoWorkflow(
  databaseUrl: string,
  state: MockContainmentState,
  incidentProvider = new MockIncidentProvider({
    openStore: () => createLibSqlOperationalStore({ url: databaseUrl }),
  }),
  runbookRoot = resolve(process.cwd(), "src/mastra/runbooks"),
) {
  return createIncidentIngestionWorkflow(
    () => createLibSqlOperationalStore({ url: databaseUrl }),
    {
      openVectorStore: () => new LibSqlRunbookVectorStore({ url: databaseUrl }),
      embedder: new DeterministicRunbookEmbedder(),
      retrieve: (store, vector, embedder, input) =>
        retrieveRunbook(store, vector, embedder, input, {
          threshold: -1,
          topK: 3,
          clock: fixedClock(fixedNow),
        }),
    },
    {
      identityProvider: new MockIdentityEvidenceProvider({
        openBaselineStore: () =>
          createLibSqlOperationalStore({ url: databaseUrl }),
        requireDemoBaseline: true,
      }),
      endpointProvider: new MockEndpointEvidenceProvider({
        openBaselineStore: () =>
          createLibSqlOperationalStore({ url: databaseUrl }),
        requireDemoBaseline: true,
      }),
      cloudProvider: new MockCloudEvidenceProvider({
        openBaselineStore: () =>
          createLibSqlOperationalStore({ url: databaseUrl }),
        requireDemoBaseline: true,
      }),
      clock: fixedClock(fixedNow),
      supervisor: async () => ({
        scopeValidated: true,
        specialists: ["identity", "endpoint", "cloud"],
      }),
      identityInvestigator: async ({ facts }) => ({
        citedFactTokens: facts.map((fact) => fact.factToken),
        gaps: [],
        contradictionFlags: [],
      }),
      endpointInvestigator: async ({ facts }) => ({
        citedFactTokens: facts.map((fact) => fact.factToken),
        gaps: [],
        contradictionFlags: [],
      }),
      cloudInvestigator: async ({ facts }) => ({
        citedFactTokens: facts.map((fact) => fact.factToken),
        gaps: [],
        contradictionFlags: [],
      }),
      correlationAnalyst: async ({ candidate }) => candidate,
    },
    {
      planner: deterministicResponsePlanner,
      runbookRoot,
    },
    {
      enabled: true,
      provider: incidentProvider,
      state,
      mode: "mock",
      timeoutMs: 1_000,
      rateLimit: 8,
      clock: fixedClock(fixedNow),
    },
  );
}

export function createDemoMastra(
  databaseUrl: string,
  scenario: DemoScenario,
  demoRunId: string,
  incidentProvider?: MockIncidentProvider,
): Mastra {
  const workflow = createDemoWorkflow(
    databaseUrl,
    mockState(scenario, demoRunId),
    incidentProvider,
  );
  return new Mastra({
    storage: new LibSQLStore({
      id: demoId("mastra", demoRunId),
      url: databaseUrl,
    }),
    workflows: { incidentIngestionWorkflow: workflow },
  });
}

/**
 * Builds a demo runtime with operational state and trace state physically
 * separated.  MastraCompositeStore retains the real operational store for
 * workflow snapshots, approvals and scores while routing only the official
 * `observability` domain to the run-owned trace store.
 *
 * The caller must close the returned owner.  Its lifecycle is intentionally
 * ordered: flush the exporter, let Mastra shut down observability, restore the
 * process default, then release the two parent LibSQL clients.
 */
export async function createTracedDemoMastra(
  input: Readonly<{
    databaseUrl: string;
    traceDatabaseUrl: string;
    demoRunId: string;
    workflow: ReturnType<typeof createDemoWorkflow>;
  }>,
) {
  const operationalStore = new LibSQLStore({
    id: demoId("mastra", input.demoRunId),
    url: input.databaseUrl,
  });
  const traceStore = new LibSQLStore({
    id: demoId("mastra-trace", input.demoRunId),
    url: input.traceDatabaseUrl,
  });
  const storage = new MastraCompositeStore({
    id: demoId("mastra-composite", input.demoRunId),
    default: operationalStore,
    domains: { observability: traceStore.stores.observability },
  });
  // The composite retains parent stores specifically so their adapter-level
  // initialization is serialized.  Complete it before the operational worker
  // opens another client: MastraStorageExporter otherwise first touches the
  // composite while the worker is writing workflow state.
  await operationalStore.init();
  await traceStore.init();
  await storage.init();
  const runtimeObservability = createPhase4Observability();
  const restoreObservability = installPhase4Observability(runtimeObservability);
  const mastra = new Mastra({
    storage,
    observability: runtimeObservability,
    // Register the official function scorers with the same runtime that owns
    // demo traces. Registration is not execution: pending-HITL runs emit no
    // observed score and no score row.
    scorers: phase10MastraScorers,
    workflows: { incidentIngestionWorkflow: input.workflow },
  });
  let closed = false;

  return {
    mastra,
    observability: runtimeObservability,
    operationalStore,
    traceStore,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      try {
        await runtimeObservability.flush();
        await shutdownDemoMastra(mastra);
      } finally {
        restoreObservability();
        await traceStore.close();
        await operationalStore.close();
      }
    },
  };
}

export async function shutdownDemoMastra(mastra: Mastra): Promise<void> {
  // Mastra currently emits a completion diagnostic through console.log. This
  // CLI's stdout is a versioned JSONL boundary, so route it to stderr.
  const write = console.log;
  console.log = (...values: unknown[]) =>
    process.stderr.write(`${values.map(String).join(" ")}\n`);
  try {
    await mastra.shutdown();
  } finally {
    console.log = write;
  }
}
