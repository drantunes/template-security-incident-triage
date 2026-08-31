import { Mastra } from "@mastra/core/mastra";
import { MastraCompositeStore } from "@mastra/core/storage";
import { LibSQLStore } from "@mastra/libsql";
import { afterEach, describe, expect, it } from "vitest";

import {
  createPhase4Observability,
  phase10RecordedTraceId,
} from "../../src/mastra/observability.js";
import {
  advanceWorkflowPhase10Trace,
  readWorkflowPhase10Trace,
} from "../../src/mastra/phase10-trace-context.js";
import {
  phase10TraceManifest,
  validateTraceManifest,
  type SanitizedTraceBoundary,
} from "../../src/mastra/evals/trace-contract.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";
import { runMockDemo } from "../../src/demo/runner.js";
import { demoId, fixtureForScenario } from "../../src/demo/fixtures.js";
import { createLibSqlOperationalStore } from "../../src/db/libsql-operational-store.js";
import { pathToFileURL } from "node:url";
import {
  createDemoWorkflow,
  createTracedDemoMastra,
  mockState,
} from "../../src/demo/runtime.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("Phase 10 public trace API", () => {
  it("registers official scorers on the isolated runner without emitting a pending score", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const runId = demoId("demo", "phase10-scorer-registry");
    const runtime = await createTracedDemoMastra({
      databaseUrl: database.url,
      traceDatabaseUrl: pathToFileURL(`${database.directory}/trace.db`).href,
      demoRunId: runId,
      workflow: createDemoWorkflow(database.url, mockState("privilege", runId)),
    });
    try {
      expect(Object.keys(runtime.mastra.listScorers() ?? {}).sort()).toEqual([
        "phase10Attribution",
        "phase10Compliance",
        "phase10Hallucination",
        "phase10Safety",
        "phase10Severity",
      ]);
      // Merely registering the runner must not bypass the pending manifest.
      const scores = await runtime.operationalStore.getStore("scores");
      expect(scores).toBeDefined();
    } finally {
      await runtime.close();
    }
  });

  it("reads approve, reject, and expire product flows from the dedicated trace store", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const flows = [
      ["privilege", "approve", "approved"],
      ["country", "reject", "rejected"],
      ["device", "expire", "expired"],
    ] as const;
    for (const [scenario, decision, disposition] of flows) {
      const runKey = `phase10-public-trace-${scenario}`;
      const result = await runMockDemo({
        root: database.directory,
        scenario,
        decision,
        runKey,
        timeoutMs: 8_000,
      });
      expect(result.exitCode).toBe(0);

      const operational = new LibSQLStore({
        id: `phase10-operational-reader-${scenario}`,
        url: pathToFileURL(result.journal.databasePath).href,
      });
      const trace = new LibSQLStore({
        id: `phase10-trace-reader-${scenario}`,
        url: pathToFileURL(result.journal.traceDatabasePath).href,
      });
      const storage = new MastraCompositeStore({
        id: `phase10-composite-reader-${scenario}`,
        default: operational,
        domains: { observability: trace.stores.observability },
      });
      // Parent stores are explicitly initialized before the composite, just
      // as the production runner does, so reopening is free of init races.
      await operational.init();
      await trace.init();
      await storage.init();
      const readerObservability = createPhase4Observability();
      const reader = new Mastra({
        storage,
        observability: readerObservability,
      });
      const store = createLibSqlOperationalStore({
        url: pathToFileURL(result.journal.databasePath).href,
      });
      try {
        const carrierRow = await store.execute({
          sql: "SELECT phase10_trace_json FROM workflow_runs WHERE run_id = ?",
          args: [result.journal.workflowRunId ?? ""],
        });
        const carrier = JSON.parse(
          String(carrierRow.rows[0]?.phase10_trace_json ?? ""),
        ) as {
          traceId: string;
          scope?: {
            tenantId: string;
            incidentId: string;
            runId: string;
            correlationId: string;
          };
        };
        const fixture = fixtureForScenario(scenario, result.journal.demoRunId);
        expect(reader.observability).toBe(readerObservability);
        const recorded = await readerObservability.getRecordedTrace({
          traceId: phase10RecordedTraceId({
            traceId: carrier.traceId,
            tenantId: carrier.scope?.tenantId ?? fixture.tenantId,
            incidentId: carrier.scope?.incidentId ?? fixture.sourceEventId,
            runId: carrier.scope?.runId ?? fixture.sourceEventId,
            correlationId:
              carrier.scope?.correlationId ??
              demoId("request", result.journal.demoRunId),
          }),
        });
        expect(recorded).not.toBeNull();
        const boundaries: SanitizedTraceBoundary[] = recorded!.spans.map(
          (span) => ({
            spanId: span.id,
            traceId: span.traceId,
            name: String(
              ((span.attributes ?? {}) as Record<string, unknown>).boundary,
            ),
            ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
            startMs: span.startTime.getTime(),
            ...(span.endTime ? { endMs: span.endTime.getTime() } : {}),
            attributes: (span.attributes ?? {}) as Record<string, unknown>,
          }),
        );
        const surface = JSON.stringify(
          recorded!.spans.map((span) => ({
            id: span.id,
            traceId: span.traceId,
            parentSpanId: span.parentSpanId,
            attributes: span.attributes,
            input: span.input,
            output: span.output,
          })),
        );
        expect(
          validateTraceManifest(
            boundaries,
            phase10TraceManifest(scenario, disposition),
            [surface],
            ["phase10-secret-canary", "canary-sensitive", "198.51.100.8"],
          ),
        ).toEqual([]);
        // These probes mutate the public readback of a real product trace;
        // they never manufacture spans or bypass Mastra storage.
        expect(
          validateTraceManifest(
            boundaries.filter((span) => span.name !== "gather.identity"),
            phase10TraceManifest(scenario, disposition),
            [surface],
            ["phase10-secret-canary"],
          ),
        ).toContain("missing:gather.identity");
        const gather = boundaries.find(
          (span) => span.name === "gather.identity",
        )!;
        expect(
          validateTraceManifest(
            boundaries.map((span) =>
              span === gather
                ? { ...span, parentSpanId: boundaries[0]!.spanId }
                : span,
            ),
            phase10TraceManifest(scenario, disposition),
            [surface],
            ["phase10-secret-canary"],
          ),
        ).toContain("parent:gather.identity:workflow.context");
        expect(
          validateTraceManifest(
            boundaries,
            phase10TraceManifest(scenario, disposition),
            [`${surface}:phase10-secret-canary`],
            ["phase10-secret-canary"],
          ),
        ).toContain("canary:phase10-secret-canary");
        // Only the trace DB receives observability tables; workflow state
        // remains readable from the operational parent.
        expect(await operational.getStore("workflows")).toBeDefined();
        expect(await trace.getStore("observability")).toBeDefined();
      } finally {
        store.close();
        await readerObservability.shutdown();
        await trace.close();
        await operational.close();
      }
    }
  }, 30_000);

  it("rejects a stale serialized carrier even when the trace id is unchanged", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const result = await runMockDemo({
      root: database.directory,
      scenario: "privilege",
      decision: "approve",
      runKey: "phase10-stale-carrier",
      timeoutMs: 8_000,
    });
    expect(result.exitCode).toBe(0);
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    try {
      const runId = result.journal.workflowRunId!;
      const row = await store.execute({
        sql: "SELECT tenant_id, incident_id FROM workflow_runs WHERE run_id = ?",
        args: [runId],
      });
      const tenantId = String(row.rows[0]?.tenant_id);
      const incidentId = String(row.rows[0]?.incident_id);
      const previous = await readWorkflowPhase10Trace(store, {
        tenantId,
        incidentId,
        workflowRunId: runId,
      });
      expect(previous).toBeDefined();
      const first = await advanceWorkflowPhase10Trace(store, {
        tenantId,
        incidentId,
        workflowRunId: runId,
        previous: previous!,
        next: { ...previous!, parentSpanId: "fresh-parent-span" },
      });
      const staleOverwrite = await advanceWorkflowPhase10Trace(store, {
        tenantId,
        incidentId,
        workflowRunId: runId,
        previous: previous!,
        next: { ...previous!, parentSpanId: "stale-parent-span" },
      });
      expect(first).toBe(true);
      expect(staleOverwrite).toBe(false);
    } finally {
      store.close();
    }
  }, 30_000);
});
