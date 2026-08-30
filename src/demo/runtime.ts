import { resolve } from "node:path";

import { Mastra } from "@mastra/core/mastra";
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

export const webhookSecret = "phase9-demo-webhook-secret-not-for-production";
export const decisionSecret = "phase9-demo-decision-secret-not-for-production";
export const resumeSecret = "phase9-demo-resume-secret-not-for-production";
// The webhook owns its received timestamp. Keep the deterministic workflow
// clock just ahead of that write so the operational monotonicity trigger is
// preserved even when this harness is run years after its fixture was added.
export const fixedNow = new Date(Date.now() + 120_000).toISOString();

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
      runbookRoot: resolve(process.cwd(), "src/mastra/runbooks"),
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
