import {
  access,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import { DEMO_EXIT } from "../../src/demo/contracts.js";
import { demoId } from "../../src/demo/fixtures.js";
import { semanticDatabaseHash } from "../../src/demo/journal.js";
import { readDemoEvidenceBaseline } from "../../src/demo/evidence-baseline.js";
import {
  createLibSqlOperationalStore,
  createReadOnlyLibSqlOperationalStore,
} from "../../src/db/libsql-operational-store.js";
import {
  calculatePlanHash,
  canonicalizePlanValue,
} from "../../src/containment/plan-canonicalization.js";
import { MockEndpointEvidenceProvider } from "../../src/providers/endpoint-evidence-provider.js";
import { MockIdentityEvidenceProvider } from "../../src/providers/identity-evidence-provider.js";
import { MockCloudEvidenceProvider } from "../../src/providers/cloud-evidence-provider.js";
import {
  cleanupDemo,
  inspectDemo,
  runMockDemo as runMockDemoProduction,
} from "../../src/demo/runner.js";
import { observeDemoSurfaces } from "../../src/demo/surfaces.js";
import { preflightDemo } from "../../src/demo/preflight.js";
import { INCIDENT_INGESTION_WORKFLOW_ID } from "../../src/db/workflow-run-operations.js";
import { createIncidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";

const roots: string[] = [];
const execFileAsync = promisify(execFile);
const CLI_TEST_TIMEOUT_MS = 12_000;
const DEMO_TEST_BUDGET_MS = 8_000;

/**
 * The E2E boundary must never leave a child alive after a hung CLI/observer.
 * The bounded child acknowledges SIGTERM before exit, so callers never race a
 * PID probe (which can observe a short-lived zombie under CI load) with their
 * owned-root cleanup.
 */
function invokeBoundedNode(
  args: readonly string[],
  options: Readonly<{ timeoutMs?: number; nodePath?: string }> = {},
) {
  return execFileAsync(
    options.nodePath ?? process.execPath,
    ["--no-deprecation", ...args],
    {
      cwd: process.cwd(),
      timeout: options.timeoutMs ?? CLI_TEST_TIMEOUT_MS,
      killSignal: "SIGTERM",
    },
  );
}

function invokeDemo(...args: string[]) {
  const boundedArgs =
    args[0] === "run" && !args.includes("--timeout-ms")
      ? [...args, "--timeout-ms", String(DEMO_TEST_BUDGET_MS)]
      : args;
  return invokeBoundedNode([
    "--import",
    "tsx",
    "scripts/phase9-demo.mts",
    ...boundedArgs,
  ]);
}

function invokeSurfaces(
  root: string,
  demoRunId: string,
  options: Readonly<{ nodePath?: string }> = {},
) {
  return invokeBoundedNode(
    [
      "--import",
      "tsx",
      "scripts/phase9-demo-surfaces.mts",
      "--demo-run-id",
      demoRunId,
      "--root",
      root,
    ],
    options,
  );
}

function runMockDemo(options: Parameters<typeof runMockDemoProduction>[0]) {
  return runMockDemoProduction({
    ...options,
    timeoutMs: options.timeoutMs ?? DEMO_TEST_BUDGET_MS,
  });
}

async function observeByCli(root: string, demoRunId: string) {
  return invokeSurfaces(root, demoRunId);
}

async function expectObserverError(
  root: string,
  demoRunId: string,
  exitCode: number,
) {
  try {
    await observeByCli(root, demoRunId);
    throw new Error("observer unexpectedly succeeded");
  } catch (error) {
    const failure = error as Error & {
      code?: number;
      stdout?: string;
      stderr?: string;
    };
    expect(failure.code).toBe(exitCode);
    expect(failure.stderr ?? "").toBe("");
    const lines = (failure.stdout ?? "").trim().split("\n");
    expect(lines).toHaveLength(1);
    return JSON.parse(lines[0]!) as Record<string, unknown>;
  }
}

async function terminalDemo(
  root: string,
  scenario: "privilege" | "country" | "device",
  runKey: string,
) {
  await runMockDemo({ scenario, runKey, root });
  return runMockDemo({ scenario, runKey, root, decision: "approve" });
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("Phase 9 hermetic demos", () => {
  it("freezes the shared ingestion workflow and its step identifiers", () => {
    const workflow = createIncidentIngestionWorkflow(
      undefined,
      {},
      {},
      {},
      { enabled: true, mode: "mock" },
    );
    expect(workflow.id).toBe(INCIDENT_INGESTION_WORKFLOW_ID);
    expect(Object.keys(workflow.steps)).toEqual([
      "start-investigation",
      "load-investigation-context",
      "soc-supervisor-validate-scope",
      "gather-identity-evidence",
      "gather-endpoint-evidence",
      "gather-cloud-evidence",
      "correlate-events",
      "prepare-runbook-retrieval",
      "retrieve-runbook",
      "classify-severity",
      "generate-summary",
      "propose-containment",
      "validate-containment",
      "request-approval",
      "open-external-incident",
      "await-approval",
      "execute-containment",
      "verify-containment",
      "update-external-incident",
      "finalize-incident",
    ]);
  });

  it("keeps the tutorial on versioned hermetic CLI commands", async () => {
    const tutorial = await readFile(
      join(process.cwd(), "docs/phase-9-demo-tutorial.md"),
      "utf8",
    );
    expect(tutorial).toContain("npm --silent run demo --");
    expect(tutorial).toContain("npm --silent run demo:surfaces --");
    expect(tutorial).toContain("--decision expire");
    expect(tutorial).not.toContain("npm run dev:server");
    expect(tutorial).not.toContain("npm run dev:studio");
    expect(tutorial).not.toMatch(/^curl\s/mu);
  });

  it("flushes complete large and error JSONL observations on the minimum Node runtime when available", async () => {
    const minimumNode = "/Users/drantunes/.nvm/versions/node/v22.13.1/bin/node";
    try {
      await access(minimumNode);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    const root = await mkdtemp(join(tmpdir(), "phase9-node22-surface-flush-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-node22-surface-flush-key",
      root,
    });
    const observation = await invokeSurfaces(root, result.journal.demoRunId, {
      nodePath: minimumNode,
    });
    expect(Buffer.byteLength(observation.stdout, "utf8")).toBeGreaterThan(8192);
    expect(observation.stdout.endsWith("\n")).toBe(true);
    expect(JSON.parse(observation.stdout)).toMatchObject({
      type: "surface_observation",
      demoRunId: result.journal.demoRunId,
      state: "awaiting_approval",
    });
    try {
      await invokeBoundedNode(
        [
          "--import",
          "tsx",
          "scripts/phase9-demo-surfaces.mts",
          "--demo-run-id",
          "bad",
        ],
        { nodePath: minimumNode },
      );
      throw new Error("expected observer usage to fail");
    } catch (error) {
      const failure = error as Error & { code?: number; stdout?: string };
      expect(failure.code).toBe(DEMO_EXIT.usage);
      expect(failure.stdout?.endsWith("\n")).toBe(true);
      expect(JSON.parse(failure.stdout ?? "{}")).toMatchObject({
        type: "error",
        code: "DEMO_USAGE_INVALID",
      });
    }
  }, 30_000);

  it("terminates a stalled child within the harness budget and leaves no artifact", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-bounded-child-"));
    roots.push(root);
    const pidPath = join(root, "child.pid");
    const terminatedPath = join(root, "child.terminated");
    const artifactPath = join(root, "late-artifact");
    const started = performance.now();
    let termination: unknown;
    try {
      await invokeBoundedNode(
        [
          "-e",
          "const fs=require('node:fs'); fs.writeFileSync(process.argv[1], String(process.pid)); process.on('SIGTERM',()=>{fs.writeFileSync(process.argv[2],'terminated');process.exit(143)}); setTimeout(() => fs.writeFileSync(process.argv[3], 'late'), 5000)",
          pidPath,
          terminatedPath,
          artifactPath,
        ],
        { timeoutMs: 100 },
      );
    } catch (error) {
      termination = error;
    }
    expect(termination).toSatisfy(
      (
        error: { killed?: boolean; signal?: string; code?: number } | undefined,
      ) =>
        error?.killed === true ||
        error?.signal === "SIGTERM" ||
        error?.code === 143,
    );
    expect(performance.now() - started).toBeLessThan(2_000);
    expect(await readFile(pidPath, "utf8")).toMatch(/^\d+$/u);
    expect(await readFile(terminatedPath, "utf8")).toBe("terminated");
    await expect(access(artifactPath)).rejects.toThrow();
  });

  it("cleans an inspected database using a semantic, WAL-safe precondition", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-inspect-cleanup-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-inspect-cleanup-key",
      root,
    });
    const observer = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    await observer.execute({ sql: "SELECT status FROM incidents" });
    observer.close();
    expect((await cleanupDemo(root, result.journal.demoRunId)).state).toBe(
      "cleaned",
    );
  });

  it("cleans a timeout journal safely and refuses silent rerun", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-timeout-cleanup-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-timeout-cleanup-key",
      root,
      timeoutMs: 1,
    });
    expect(result.exitCode).toBe(DEMO_EXIT.timeout);
    expect(result.journal.state).toBe("timed_out");
    await expect(
      runMockDemo({
        scenario: "privilege",
        runKey: "phase9-timeout-cleanup-key",
        root,
      }),
    ).rejects.toThrow("DEMO_RECOVERY_REQUIRED_INSPECT_OR_CLEANUP");
    expect((await cleanupDemo(root, result.journal.demoRunId)).state).toBe(
      "cleaned",
    );
  });

  it("preserves a concurrent database mutation instead of rebasing cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-cleanup-conflict-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-cleanup-conflict-key",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    await store.execute({
      sql: "CREATE TABLE concurrent_owner_marker (value TEXT NOT NULL) STRICT",
    });
    await store.execute({
      sql: "INSERT INTO concurrent_owner_marker(value) VALUES ('preserve-me')",
    });
    store.close();
    await expect(cleanupDemo(root, result.journal.demoRunId)).rejects.toThrow(
      "DEMO_CLEANUP_PRECONDITION_FAILED",
    );
    expect((await inspectDemo(root, result.journal.demoRunId))?.state).toBe(
      "cleanup_blocked",
    );
    await expect(access(result.journal.databasePath)).resolves.toBeUndefined();
  });

  it("makes two concurrent CLI cleanups converge to cleaned without a CAS exit", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "phase9-concurrent-cli-cleanup-"),
    );
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-concurrent-cli-cleanup-key",
      root,
    });
    const invoke = () =>
      invokeDemo(
        "cleanup",
        "--demo-run-id",
        result.journal.demoRunId,
        "--confirm-cleanup",
        "--root",
        root,
      );
    const [left, right] = await Promise.all([invoke(), invoke()]);
    for (const invocation of [left, right]) {
      expect(JSON.parse(invocation.stdout)).toMatchObject({
        type: "cleanup",
        state: "cleaned",
      });
    }
    expect((await inspectDemo(root, result.journal.demoRunId))?.state).toBe(
      "cleaned",
    );
  }, 30_000);

  it("revalidates a terminal rerun and fails closed after severity tamper", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-terminal-tamper-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-terminal-tamper-key",
      decision: "approve",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    await store.execute({
      sql: "UPDATE incidents SET severity = NULL WHERE id = ?",
      args: [result.journal.incidentId!],
    });
    store.close();
    await expect(
      runMockDemo({
        scenario: "privilege",
        runKey: "phase9-terminal-tamper-key",
        root,
      }),
    ).rejects.toThrow("DEMO_TERMINAL_PROJECTION_DIVERGED");
  });

  it("fails terminal verification after a schema-valid action/input tamper", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-action-tamper-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "country",
      runKey: "phase9-action-tamper-key",
      decision: "reject",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    await store.execute({
      sql: `UPDATE containment_actions SET action_type = 'restore_previous_role',
        input_json = '{"role":"admin"}'
        WHERE plan_id = ? AND ordinal = 0`,
      args: [result.journal.planId!],
    });
    store.close();
    await expect(
      runMockDemo({
        scenario: "country",
        runKey: "phase9-action-tamper-key",
        root,
      }),
    ).rejects.toThrow("DEMO_ACTION_PROJECTION_DIVERGED");
  });

  it("rejects a coordinated plan/action rewrite while the approved hash stays old", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "phase9-coordinated-plan-tamper-"),
    );
    roots.push(root);
    const result = await runMockDemo({
      scenario: "country",
      runKey: "phase9-coordinated-plan-tamper-key",
      decision: "reject",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    const stored = await store.execute({
      sql: "SELECT plan_json, plan_hash FROM containment_plans WHERE id = ?",
      args: [result.journal.planId!],
    });
    const plan = JSON.parse(String(stored.rows[0]?.plan_json)) as {
      actions: Array<{ targetId: string; input: Record<string, unknown> }>;
    };
    plan.actions[0]!.targetId = "subject_attacker";
    plan.actions[0]!.input = { sessionId: "session_attacker" };
    await store.execute({
      sql: "UPDATE containment_plans SET plan_json = ? WHERE id = ?",
      args: [JSON.stringify(plan), result.journal.planId!],
    });
    await store.execute({
      sql: `UPDATE containment_actions SET target_id = ?, input_json = ?
        WHERE plan_id = ? AND ordinal = 0`,
      args: [
        "subject_attacker",
        JSON.stringify({ sessionId: "session_attacker" }),
        result.journal.planId!,
      ],
    });
    const unchanged = await store.execute({
      sql: "SELECT plan_hash FROM containment_plans WHERE id = ?",
      args: [result.journal.planId!],
    });
    expect(unchanged.rows[0]?.plan_hash).toBe(stored.rows[0]?.plan_hash);
    store.close();
    await expect(
      runMockDemo({
        scenario: "country",
        runKey: "phase9-coordinated-plan-tamper-key",
        root,
      }),
    ).rejects.toThrow("DEMO_PLAN_INTEGRITY_DIVERGED");
  });

  it("rejects extra provider deliveries and effects through the versioned CLI", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "phase9-extra-provider-records-"),
    );
    roots.push(root);
    const runKey = "phase9-extra-provider-records-key";
    const invoke = (...args: string[]) => invokeDemo(...args);
    const first = await invoke(
      "run",
      "--scenario",
      "device",
      "--run-key",
      runKey,
      "--root",
      root,
    );
    const waiting = first.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { demoRunId?: string })
      .at(-1)!;
    await invoke(
      "run",
      "--scenario",
      "device",
      "--run-key",
      runKey,
      "--decision",
      "approve",
      "--root",
      root,
    );
    const journal = await inspectDemo(root, String(waiting.demoRunId));
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(journal!.databasePath).href,
    });
    const delivery = await store.execute({
      sql: `SELECT tenant_id, projection_json, workflow_run_id, correlation_id
        FROM provider_deliveries WHERE incident_id = ? LIMIT 1`,
      args: [journal!.incidentId!],
    });
    const row = delivery.rows[0]!;
    await store.execute({
      sql: `INSERT INTO provider_deliveries(
        id, provider, incident_id, tenant_id, operation, idempotency_key,
        status, attempt_count, projection_json, workflow_run_id, correlation_id,
        provider_generation
      ) VALUES (?, 'mock-incident', ?, ?, 'spurious-operation', ?, 'succeeded',
        1, ?, ?, ?, 99)`,
      args: [
        `delivery_extra_${journal!.demoRunId}`,
        journal!.incidentId!,
        row.tenant_id as string,
        `mock-incident:${journal!.incidentId}:spurious-operation`,
        row.projection_json as string,
        row.workflow_run_id as string,
        row.correlation_id as string,
      ],
    });
    await store.execute({
      sql: `INSERT INTO mock_incident_provider_effects(
        idempotency_key, operation, tenant_id, incident_id, generation,
        projection_json, external_ref
      ) VALUES (?, 'update', ?, ?, 99, ?, 'mock-incident-deadbeefcafebabe')`,
      args: [
        `mock-incident:${journal!.incidentId}:spurious-operation`,
        row.tenant_id as string,
        journal!.incidentId!,
        row.projection_json as string,
      ],
    });
    store.close();
    await expect(
      invoke(
        "run",
        "--scenario",
        "device",
        "--run-key",
        runKey,
        "--root",
        root,
      ),
    ).rejects.toMatchObject({
      code: DEMO_EXIT.verification,
      stdout: expect.stringContaining("DEMO_ACTION_PROJECTION_DIVERGED"),
    });
  }, 30_000);

  it("keeps factual JSONL context on known-run errors and avoids invented context", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-error-context-"));
    roots.push(root);
    const runKey = "phase9-error-context-key";
    const invoke = (...args: string[]) => invokeDemo(...args);
    await invoke(
      "run",
      "--scenario",
      "country",
      "--run-key",
      runKey,
      "--decision",
      "reject",
      "--root",
      root,
    );
    const demoRunId = demoId(
      "demo",
      `country\0${createHash("sha256").update(runKey).digest("hex")}`,
    );
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(join(root, `${demoRunId}.db`)).href,
    });
    await store.execute({
      sql: "UPDATE incidents SET severity = NULL WHERE id = ?",
      args: [(await inspectDemo(root, demoRunId))!.incidentId!],
    });
    store.close();
    await expect(
      invoke(
        "run",
        "--scenario",
        "country",
        "--run-key",
        runKey,
        "--root",
        root,
      ),
    ).rejects.toMatchObject({
      code: DEMO_EXIT.verification,
      stdout: expect.stringMatching(
        new RegExp(
          `"demoRunId":"${demoRunId}".*"scenario":"country".*"mode":"mock"`,
          "u",
        ),
      ),
    });
    const unknown = "demo_000000000000000000000000";
    await expect(
      invoke("inspect", "--demo-run-id", unknown, "--root", root),
    ).rejects.toMatchObject({
      code: DEMO_EXIT.cleanup,
      stdout: expect.stringContaining(`"demoRunId":"${unknown}"`),
    });
  }, 30_000);

  it("keeps deterministic context for an invalid timeout when scenario and run key are valid", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-invalid-timeout-"));
    roots.push(root);
    const runKey = "phase9-invalid-timeout-key";
    const demoRunId = demoId(
      "demo",
      `device\0${createHash("sha256").update(runKey).digest("hex")}`,
    );
    const invoke = (...args: string[]) => invokeDemo(...args);
    await expect(
      invoke(
        "run",
        "--scenario",
        "device",
        "--run-key",
        runKey,
        "--timeout-ms",
        "0",
        "--root",
        root,
      ),
    ).rejects.toMatchObject({ code: DEMO_EXIT.usage });
    try {
      await invoke(
        "run",
        "--scenario",
        "device",
        "--run-key",
        runKey,
        "--timeout-ms",
        "0",
        "--root",
        root,
      );
    } catch (error) {
      const failure = error as Error & { stdout?: string };
      expect(JSON.parse(failure.stdout ?? "{}")).toMatchObject({
        type: "error",
        code: "DEMO_TIMEOUT_INVALID",
        demoRunId,
        scenario: "device",
        mode: "mock",
      });
    }
    await expect(access(join(root, `${demoRunId}.db`))).rejects.toThrow();
  }, 30_000);

  it.each([
    [
      "action target",
      "UPDATE containment_actions SET target_id = 'attacker_target' WHERE plan_id = ? AND ordinal = 0",
    ],
    [
      "action result",
      "UPDATE containment_actions SET result_ref = 'attacker-result' WHERE plan_id = ? AND ordinal = 0",
    ],
  ])(
    "fails terminal verification after %s tamper",
    async (_name, sql) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-terminal-binding-"));
      roots.push(root);
      const result = await runMockDemo({
        scenario: "privilege",
        runKey: `phase9-terminal-binding-${_name}`,
        decision: "approve",
        root,
      });
      const store = createLibSqlOperationalStore({
        url: pathToFileURL(result.journal.databasePath).href,
      });
      await store.execute({
        sql,
        args: sql.includes("incident_id")
          ? [result.journal.incidentId!]
          : [result.journal.planId!],
      });
      store.close();
      await expect(
        runMockDemo({
          scenario: "privilege",
          runKey: `phase9-terminal-binding-${_name}`,
          root,
        }),
      ).rejects.toThrow("DEMO_ACTION_PROJECTION_DIVERGED");
    },
    30_000,
  );

  it.each([
    [
      "attempt provider result",
      "UPDATE containment_action_attempts SET provider_ref = 'attacker-ref' WHERE plan_id = ? AND attempt = 1 LIMIT 1",
    ],
    [
      "delivery status",
      "UPDATE provider_deliveries SET status = 'failed' WHERE incident_id = ? LIMIT 1",
    ],
  ])(
    "rejects %s tamper at the append-only storage boundary",
    async (_name, sql) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-immutable-tamper-"));
      roots.push(root);
      const result = await runMockDemo({
        scenario: "privilege",
        runKey: `phase9-immutable-${_name}`,
        decision: "approve",
        root,
      });
      const store = createLibSqlOperationalStore({
        url: pathToFileURL(result.journal.databasePath).href,
      });
      await expect(
        store.execute({
          sql,
          args: [
            _name === "delivery status"
              ? result.journal.incidentId!
              : result.journal.planId!,
          ],
        }),
      ).rejects.toThrow("Storage is temporarily unavailable");
      store.close();
    },
  );

  it("never adopts or cleans a pre-existing database without reservation proof", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-foreign-db-"));
    roots.push(root);
    const runKey = "phase9-foreign-db-key";
    const runKeyHash = createHash("sha256").update(runKey).digest("hex");
    const demoRunId = demoId("demo", `privilege\0${runKeyHash}`);
    const databasePath = join(root, `${demoRunId}.db`);
    // A non-empty foreign SQLite-path payload is enough for this boundary:
    // reserve must reject before libSQL tries to parse, migrate or overwrite it.
    await writeFile(databasePath, "foreign_owner_data:preserve-me\n", "utf8");
    const result = await runMockDemo({ scenario: "privilege", runKey, root });
    expect(result.exitCode).not.toBe(DEMO_EXIT.ok);
    expect(result.journal.state).toBe("failed");
    await expect(cleanupDemo(root, demoRunId)).rejects.toThrow(
      "DEMO_CLEANUP_PRECONDITION_FAILED",
    );
    expect(await readFile(databasePath, "utf8")).toBe(
      "foreign_owner_data:preserve-me\n",
    );
  });

  it("preserves a foreign SQLite sidecar after a refused reservation and cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-foreign-sidecar-"));
    roots.push(root);
    const runKey = "phase9-foreign-sidecar-key";
    const runKeyHash = createHash("sha256").update(runKey).digest("hex");
    const demoRunId = demoId("demo", `privilege\0${runKeyHash}`);
    const sidecarPath = join(root, `${demoRunId}.db-wal`);
    await writeFile(sidecarPath, "foreign_wal:preserve-me\n", "utf8");
    const result = await runMockDemo({ scenario: "privilege", runKey, root });
    expect(result.exitCode).toBe(DEMO_EXIT.cleanup);
    await expect(cleanupDemo(root, demoRunId)).rejects.toThrow(
      "DEMO_CLEANUP_PRECONDITION_FAILED",
    );
    expect(await readFile(sidecarPath, "utf8")).toBe(
      "foreign_wal:preserve-me\n",
    );
  });

  it("rejects a baseline whose persisted integrity hash no longer matches", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-baseline-tamper-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "privilege",
      runKey: "phase9-baseline-tamper-key",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    const snapshot = await store.execute({
      sql: "SELECT snapshot_json, tenant_id, subject_id FROM identity_snapshots WHERE incident_id = ?",
      args: [result.journal.incidentId!],
    });
    const altered = JSON.parse(String(snapshot.rows[0]?.snapshot_json)) as {
      identity: { actorId: string };
    };
    altered.identity.actorId = "attacker-forged";
    await store.execute({
      sql: "UPDATE identity_snapshots SET snapshot_json = ? WHERE incident_id = ?",
      args: [JSON.stringify(altered), result.journal.incidentId!],
    });
    store.close();
    await expect(
      readDemoEvidenceBaseline(
        () =>
          createLibSqlOperationalStore({
            url: pathToFileURL(result.journal.databasePath).href,
          }),
        {
          tenantId: String(snapshot.rows[0]?.tenant_id),
          incidentId: result.journal.incidentId!,
          subjectId: String(snapshot.rows[0]?.subject_id),
          workflowRunId: result.journal.workflowRunId!,
          incidentKind: "unauthorized_privilege_change",
          occurredAt: "2026-08-29T12:00:00.000Z",
        },
      ),
    ).resolves.toBeUndefined();
  });

  it.each(["privilege", "country"] as const)(
    "does not fall back to legacy %s facts when the F9 baseline is corrupt",
    async (scenario) => {
      const root = await mkdtemp(
        join(tmpdir(), `phase9-${scenario}-baseline-`),
      );
      roots.push(root);
      const result = await runMockDemo({
        scenario,
        runKey: `phase9-${scenario}-baseline-authority-key`,
        root,
      });
      const store = createLibSqlOperationalStore({
        url: pathToFileURL(result.journal.databasePath).href,
      });
      const incident = await store.execute({
        sql: "SELECT tenant_id, subject_id FROM incidents WHERE id = ?",
        args: [result.journal.incidentId!],
      });
      await store.execute({
        sql: "UPDATE identity_snapshots SET integrity_hash = ? WHERE incident_id = ?",
        args: ["0".repeat(64), result.journal.incidentId!],
      });
      store.close();
      const input = {
        tenantId: String(incident.rows[0]?.tenant_id),
        incidentId: result.journal.incidentId!,
        subjectId: String(incident.rows[0]?.subject_id),
        workflowRunId: result.journal.workflowRunId!,
        incidentKind:
          scenario === "privilege"
            ? ("unauthorized_privilege_change" as const)
            : ("disallowed_country_login" as const),
        occurredAt: "2026-08-29T12:00:00.000Z",
        ...(scenario === "privilege"
          ? {
              actorId: "actor_authority",
              roleChange: {
                previousRole: "member" as const,
                currentRole: "admin" as const,
              },
              changeApproved: false,
            }
          : { ip: "198.51.100.8" }),
      };
      const provider =
        scenario === "privilege"
          ? new MockIdentityEvidenceProvider({
              requireDemoBaseline: true,
              openBaselineStore: () =>
                createLibSqlOperationalStore({
                  url: pathToFileURL(result.journal.databasePath).href,
                }),
            })
          : new MockCloudEvidenceProvider({
              requireDemoBaseline: true,
              openBaselineStore: () =>
                createLibSqlOperationalStore({
                  url: pathToFileURL(result.journal.databasePath).href,
                }),
            });
      const inspected = await provider.inspect(input, {
        signal: new AbortController().signal,
        attempt: 1,
      });
      expect(inspected).toMatchObject({
        status: "invalid_response",
        error: { code: "INVALID_RESPONSE" },
      });
    },
    30_000,
  );
  it.each([
    ["privilege", "approve"],
    ["country", "reject"],
    ["device", "approve"],
  ] as const)(
    "runs %s through the versioned CLI against clean storage (%s)",
    async (scenario, decision) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-cli-"));
      roots.push(root);
      const key = `phase9-cli-${scenario}-key`;
      const invoke = async (...args: string[]) => invokeDemo(...args);
      const first = await invoke(
        "run",
        "--scenario",
        scenario,
        "--run-key",
        key,
        "--root",
        root,
      );
      const waiting = first.stdout
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { type: string; demoRunId?: string })
        .find((record) => record.type === "approval_required");
      expect(waiting?.demoRunId).toBeTruthy();
      const suspended = JSON.parse(
        (await observeByCli(root, String(waiting?.demoRunId))).stdout,
      ) as {
        state: string;
        dashboard: {
          incident: { status: string; workflowRunId: string | null };
          approval: { decision: string | null } | null;
          actions: Array<{ status: string }>;
          outcome: { status: string };
          timeline: readonly unknown[];
        };
        sse: { events: readonly unknown[] };
        mastraRun: { status: string; workflowRunId: string };
      };
      expect(suspended).toMatchObject({
        state: "awaiting_approval",
        dashboard: {
          incident: {
            status: "awaiting_approval",
            workflowRunId: expect.any(String),
          },
          approval: { decision: null },
          outcome: { status: "pending" },
        },
        mastraRun: { status: "running" },
      });
      expect(suspended.dashboard.actions).toHaveLength(2);
      expect(
        suspended.dashboard.actions.every(
          (action) => action.status === "pending",
        ),
      ).toBe(true);
      expect(suspended.sse.events).toEqual(suspended.dashboard.timeline);
      expect(suspended.mastraRun.workflowRunId).toBe(
        suspended.dashboard.incident.workflowRunId,
      );
      const terminal = await invoke(
        "run",
        "--scenario",
        scenario,
        "--run-key",
        key,
        "--decision",
        decision,
        "--root",
        root,
      );
      const terminalRecords = terminal.stdout
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(terminalRecords.map((record) => record.type)).toEqual([
        "terminal",
        "verification",
      ]);
      expect(
        terminalRecords.every((record) => record.schemaVersion === 1),
      ).toBe(true);
      expect(terminalRecords[1]).toMatchObject({
        demoRunId: waiting?.demoRunId,
        scenario,
        state: "terminal",
        outcome: decision === "approve" ? "contained" : "rejected",
        runbookId:
          scenario === "privilege"
            ? "RB-IDENTITY-001"
            : scenario === "country"
              ? "RB-IDENTITY-002"
              : "RB-IDENTITY-003",
      });
      const journal = await inspectDemo(root, String(waiting?.demoRunId));
      expect(journal).toBeDefined();
      // The same run is observed through the versioned local adapter for the
      // existing F7 dashboard DTO and SSE replay interfaces. This is the
      // hermetic equivalent of the authenticated UI/API when Studio is not
      // started by the F9 harness.
      const surfaces = await observeDemoSurfaces(journal!);
      expect(surfaces.ids).toEqual({
        incidentId: journal!.incidentId,
        workflowRunId: journal!.workflowRunId,
        approvalId: journal!.approvalId,
        planId: journal!.planId,
      });
      expect(surfaces.dashboard.incident).toMatchObject({
        incidentId: journal!.incidentId,
        workflowRunId: journal!.workflowRunId,
        status: "closed",
      });
      expect(surfaces.dashboard.approval?.approvalId).toBe(journal!.approvalId);
      expect(surfaces.mastraRun).toMatchObject({
        workflowId: INCIDENT_INGESTION_WORKFLOW_ID,
        workflowRunId: journal!.workflowRunId,
        incidentId: journal!.incidentId,
        status: "completed",
      });
      expect(surfaces.sse.events).toEqual(surfaces.dashboard.timeline);
      expect(surfaces.sse.events.at(-1)?.incidentId).toBe(journal!.incidentId);
      const authoritative = createLibSqlOperationalStore({
        url: pathToFileURL(journal!.databasePath).href,
      });
      const projection = await authoritative.execute({
        sql: `SELECT i.status AS incident_status, i.severity, w.workflow_id,
          w.status AS workflow_status, a.decision, p.plan_json,
          (SELECT count(*) FROM containment_actions ca WHERE ca.plan_id = p.id) AS action_count,
          (SELECT count(*) FROM containment_action_attempts aa
            WHERE aa.plan_id = p.id AND aa.approval_id = a.id
              AND aa.status = 'completed' AND aa.verification = 'verified') AS verified_attempt_count,
          (SELECT count(*) FROM provider_deliveries pd WHERE pd.incident_id = i.id
            AND pd.status = 'succeeded') AS delivery_count,
          (SELECT count(*) FROM timeline_events te WHERE te.incident_id = i.id
            AND te.type = 'approval.decided') AS decision_events
          FROM incidents i
          JOIN workflow_runs w ON w.incident_id = i.id AND w.run_id = ?
          JOIN approvals a ON a.id = ? AND a.incident_id = i.id
          JOIN containment_plans p ON p.id = a.plan_id AND p.incident_id = i.id
          WHERE i.id = ?`,
        args: [
          journal!.workflowRunId!,
          journal!.approvalId!,
          journal!.incidentId!,
        ],
      });
      const actionProjection = await authoritative.execute({
        sql: `SELECT action_id, action_type, target_id, input_json,
          idempotency_key, status, result_ref
          FROM containment_actions WHERE incident_id = ? AND plan_id = ?
          ORDER BY ordinal`,
        args: [journal!.incidentId!, journal!.planId!],
      });
      const attempts = await authoritative.execute({
        sql: `SELECT action_id, approval_id, idempotency_key, attempt, status,
          verification, provider_ref, fence_token
          FROM containment_action_attempts
          WHERE incident_id = ? AND plan_id = ? ORDER BY action_id, attempt`,
        args: [journal!.incidentId!, journal!.planId!],
      });
      const effects = await authoritative.execute({
        sql: `SELECT action_id, action_type, target_id, input_json, attempt,
          fence_token, provider_ref FROM mock_containment_effects
          WHERE incident_id = ? AND plan_id = ? ORDER BY action_id`,
        args: [journal!.incidentId!, journal!.planId!],
      });
      const deliveries = await authoritative.execute({
        sql: `SELECT operation, idempotency_key, status, attempt_count,
          workflow_run_id, projection_json, external_ref, provider_generation
          FROM provider_deliveries WHERE incident_id = ? ORDER BY operation`,
        args: [journal!.incidentId!],
      });
      const providerEffects = await authoritative.execute({
        sql: `SELECT operation, idempotency_key, generation, projection_json,
          external_ref FROM mock_incident_provider_effects
          WHERE incident_id = ? ORDER BY idempotency_key`,
        args: [journal!.incidentId!],
      });
      expect(projection.rows).toHaveLength(1);
      expect(projection.rows[0]).toMatchObject({
        incident_status: "closed",
        workflow_status: "completed",
        workflow_id: INCIDENT_INGESTION_WORKFLOW_ID,
        decision: decision === "approve" ? "approved" : "rejected",
        action_count: 2,
        delivery_count: 2,
        decision_events: 1,
      });
      expect(projection.rows[0]?.severity).toBe(terminalRecords[1]?.severity);
      expect(Number(projection.rows[0]?.verified_attempt_count)).toBe(
        decision === "approve" ? 2 : 0,
      );
      const plan = JSON.parse(String(projection.rows[0]?.plan_json)) as {
        planHash: string;
        actions: Array<{
          actionId: string;
          type: string;
          targetId: string;
          input: Record<string, unknown>;
        }>;
      };
      expect(calculatePlanHash(plan)).toBe(plan.planHash);
      expect(actionProjection.rows).toHaveLength(plan.actions.length);
      for (const [ordinal, action] of plan.actions.entries()) {
        const persisted = actionProjection.rows[ordinal]!;
        expect(persisted).toMatchObject({
          action_id: action.actionId,
          action_type: action.type,
          target_id: action.targetId,
          idempotency_key: `${journal!.planId}:${action.actionId}`,
          status: decision === "approve" ? "completed" : "pending",
        });
        expect(
          canonicalizePlanValue(JSON.parse(String(persisted.input_json))),
        ).toBe(canonicalizePlanValue(action.input));
      }
      expect(attempts.rows).toHaveLength(decision === "approve" ? 2 : 0);
      expect(effects.rows).toHaveLength(decision === "approve" ? 2 : 0);
      for (const action of plan.actions) {
        const attempt = attempts.rows.find(
          (row) => row.action_id === action.actionId,
        );
        const effect = effects.rows.find(
          (row) => row.action_id === action.actionId,
        );
        if (decision === "reject") {
          expect(attempt).toBeUndefined();
          expect(effect).toBeUndefined();
          continue;
        }
        expect(attempt).toMatchObject({
          approval_id: journal!.approvalId,
          idempotency_key: `${journal!.planId}:${action.actionId}`,
          attempt: 1,
          status: "completed",
          verification: "verified",
          provider_ref: `mock-action-${action.actionId}`,
        });
        expect(effect).toMatchObject({
          action_type: action.type,
          target_id: action.targetId,
          attempt: 1,
          fence_token: attempt?.fence_token,
          provider_ref: attempt?.provider_ref,
        });
        expect(
          canonicalizePlanValue(JSON.parse(String(effect?.input_json))),
        ).toBe(canonicalizePlanValue(action.input));
      }
      const expectedOperations = [
        "open-awaiting-approval",
        decision === "approve" ? "final-contained" : "decision-rejected",
      ].sort();
      expect(deliveries.rows.map((row) => row.operation).sort()).toEqual(
        expectedOperations,
      );
      expect(providerEffects.rows).toHaveLength(expectedOperations.length);
      for (const delivery of deliveries.rows) {
        const providerEffect = providerEffects.rows.find(
          (effect) => effect.idempotency_key === delivery.idempotency_key,
        );
        expect(delivery).toMatchObject({
          status: "succeeded",
          attempt_count: 1,
          workflow_run_id: journal!.workflowRunId,
        });
        expect(providerEffect).toMatchObject({
          operation:
            delivery.operation === "open-awaiting-approval"
              ? "create"
              : "update",
          generation: delivery.provider_generation,
          projection_json: delivery.projection_json,
          external_ref: delivery.external_ref,
        });
      }
      authoritative.close();
      await invoke(
        "cleanup",
        "--demo-run-id",
        String(waiting?.demoRunId),
        "--confirm-cleanup",
        "--root",
        root,
      );
    },
    30_000,
  );

  it("drives an expiry through the F6 dispatcher, observes it through F7, and cleans only its owned DB", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-cli-expiry-"));
    roots.push(root);
    const runKey = "phase9-cli-expiry-key";
    const invoke = (...args: string[]) => invokeDemo(...args);
    const first = await invoke(
      "run",
      "--scenario",
      "privilege",
      "--run-key",
      runKey,
      "--root",
      root,
    );
    const waiting = first.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { type: string; demoRunId?: string })
      .find((record) => record.type === "approval_required");
    const expired = await invoke(
      "run",
      "--scenario",
      "privilege",
      "--run-key",
      runKey,
      "--decision",
      "expire",
      "--root",
      root,
    );
    expect(expired.stdout).toContain('"outcome":"expired"');
    const journal = await inspectDemo(root, String(waiting?.demoRunId));
    expect(journal?.state).toBe("terminal");
    const observedByCli = await invokeSurfaces(
      root,
      String(waiting?.demoRunId),
    );
    expect(JSON.parse(observedByCli.stdout)).toMatchObject({
      type: "surface_observation",
      demoRunId: waiting?.demoRunId,
      ids: { incidentId: journal!.incidentId },
    });
    const surfaces = await observeDemoSurfaces(journal!);
    expect(surfaces.dashboard.incident.status).toBe("failed");
    expect(surfaces.mastraRun.status).toBe("completed");
    expect(surfaces.sse.events).toEqual(surfaces.dashboard.timeline);
    expect(
      surfaces.sse.events.filter((event) => event.type === "approval.expired"),
    ).toHaveLength(1);
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(journal!.databasePath).href,
    });
    const containment = await store.execute({
      sql: `SELECT
        (SELECT count(*) FROM containment_action_attempts WHERE incident_id = ?) AS attempts,
        (SELECT count(*) FROM mock_containment_effects WHERE incident_id = ?) AS effects`,
      args: [journal!.incidentId!, journal!.incidentId!],
    });
    store.close();
    expect(containment.rows[0]).toEqual({ attempts: 0, effects: 0 });
    await invoke(
      "cleanup",
      "--demo-run-id",
      String(waiting?.demoRunId),
      "--confirm-cleanup",
      "--root",
      root,
    );
    expect((await inspectDemo(root, String(waiting?.demoRunId)))?.state).toBe(
      "cleaned",
    );
  }, 30_000);

  it("fails observer preconditions before opening storage and keeps JSONL errors redacted", async () => {
    const cleanedRoot = await mkdtemp(
      join(tmpdir(), "phase9-surfaces-cleaned-"),
    );
    roots.push(cleanedRoot);
    const cleaned = await terminalDemo(
      cleanedRoot,
      "privilege",
      "phase9-surfaces-cleaned-key",
    );
    await cleanupDemo(cleanedRoot, cleaned.journal.demoRunId);
    const afterCleanup = await expectObserverError(
      cleanedRoot,
      cleaned.journal.demoRunId,
      DEMO_EXIT.cleanup,
    );
    expect(afterCleanup).toMatchObject({
      type: "error",
      demoRunId: cleaned.journal.demoRunId,
      scenario: "privilege",
      mode: "mock",
      code: "DEMO_CLEANUP_STATE_INVALID",
    });
    await expect(access(cleaned.journal.databasePath)).rejects.toBeDefined();
    await expect(
      access(`${cleaned.journal.databasePath}-wal`),
    ).rejects.toBeDefined();
    await expect(
      access(`${cleaned.journal.databasePath}-shm`),
    ).rejects.toBeDefined();
    expect(
      (await cleanupDemo(cleanedRoot, cleaned.journal.demoRunId)).state,
    ).toBe("cleaned");

    const missingRoot = await mkdtemp(
      join(tmpdir(), "phase9-surfaces-missing-"),
    );
    roots.push(missingRoot);
    const missing = await terminalDemo(
      missingRoot,
      "country",
      "phase9-surfaces-missing-key",
    );
    await rm(`${missing.journal.databasePath}-wal`, { force: true });
    await rm(`${missing.journal.databasePath}-shm`, { force: true });
    await rm(missing.journal.databasePath);
    const missingDatabase = await expectObserverError(
      missingRoot,
      missing.journal.demoRunId,
      DEMO_EXIT.cleanup,
    );
    expect(missingDatabase).toMatchObject({
      demoRunId: missing.journal.demoRunId,
      scenario: "country",
      mode: "mock",
      code: "DEMO_DATABASE_PRECONDITION_FAILED",
    });
    await expect(access(missing.journal.databasePath)).rejects.toBeDefined();
    await expect(
      access(`${missing.journal.databasePath}-wal`),
    ).rejects.toBeDefined();
    await expect(
      access(`${missing.journal.databasePath}-shm`),
    ).rejects.toBeDefined();

    const tamperedRoot = await mkdtemp(
      join(tmpdir(), "phase9-surfaces-tamper-"),
    );
    roots.push(tamperedRoot);
    const tampered = await terminalDemo(
      tamperedRoot,
      "country",
      "phase9-surfaces-tamper-key",
    );
    const writer = createLibSqlOperationalStore({
      url: pathToFileURL(tampered.journal.databasePath).href,
    });
    await writer.execute({
      sql: "UPDATE incidents SET severity = 'low' WHERE id = ?",
      args: [tampered.journal.incidentId!],
    });
    writer.close();
    const tamperedSeverity = await expectObserverError(
      tamperedRoot,
      tampered.journal.demoRunId,
      DEMO_EXIT.verification,
    );
    expect(tamperedSeverity).toMatchObject({
      demoRunId: tampered.journal.demoRunId,
      scenario: "country",
      mode: "mock",
      code: "DEMO_SURFACE_PRECONDITION_FAILED",
    });

    const journalRoot = await mkdtemp(
      join(tmpdir(), "phase9-surfaces-journal-"),
    );
    roots.push(journalRoot);
    const journalRun = await terminalDemo(
      journalRoot,
      "device",
      "phase9-surfaces-journal-key",
    );
    const databaseBefore = await semanticDatabaseHash(
      journalRun.journal.databasePath,
    );
    const stateStore = createReadOnlyLibSqlOperationalStore({
      url: pathToFileURL(journalRun.journal.databasePath).href,
    });
    const stateBefore = await stateStore.execute({
      sql: `SELECT
        (SELECT status FROM incidents WHERE id = ?) AS incident_status,
        (SELECT status FROM workflow_runs WHERE run_id = ?) AS workflow_status`,
      args: [journalRun.journal.incidentId!, journalRun.journal.workflowRunId!],
    });
    stateStore.close();
    const journalPath = join(
      journalRoot,
      `${journalRun.journal.demoRunId}.json`,
    );
    const journal = JSON.parse(await readFile(journalPath, "utf8")) as Record<
      string,
      unknown
    >;
    await writeFile(
      journalPath,
      `${JSON.stringify({ ...journal, checksum: "0".repeat(64) })}\n`,
      "utf8",
    );
    // Withhold the DB entirely: the observer must reject the invalid journal
    // before constructing any storage client, rather than turning this into a
    // missing-database error. Restore it before semantic/state assertions.
    const withheldDatabase = `${journalRun.journal.databasePath}.withheld`;
    await rename(journalRun.journal.databasePath, withheldDatabase);
    let badJournal: Record<string, unknown>;
    try {
      badJournal = await expectObserverError(
        journalRoot,
        journalRun.journal.demoRunId,
        DEMO_EXIT.cleanup,
      );
    } finally {
      await rename(withheldDatabase, journalRun.journal.databasePath);
    }
    expect(badJournal).toMatchObject({
      demoRunId: journalRun.journal.demoRunId,
      scenario: null,
      mode: null,
      code: "DEMO_JOURNAL_TAMPERED",
    });
    expect(await semanticDatabaseHash(journalRun.journal.databasePath)).toBe(
      databaseBefore,
    );
    const stateAfterStore = createReadOnlyLibSqlOperationalStore({
      url: pathToFileURL(journalRun.journal.databasePath).href,
    });
    const stateAfter = await stateAfterStore.execute({
      sql: `SELECT
        (SELECT status FROM incidents WHERE id = ?) AS incident_status,
        (SELECT status FROM workflow_runs WHERE run_id = ?) AS workflow_status`,
      args: [journalRun.journal.incidentId!, journalRun.journal.workflowRunId!],
    });
    stateAfterStore.close();
    expect(stateAfter.rows).toEqual(stateBefore.rows);
  }, 30_000);

  it.each([
    ["privilege", "approve"],
    ["country", "reject"],
    ["device", "approve"],
  ] as const)(
    "releases runtime and SQLite lifetime before reopening %s (%s)",
    async (scenario, decision) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-lifetime-"));
      roots.push(root);
      const result = await runMockDemo({
        scenario,
        decision,
        runKey: `phase9-lifetime-${scenario}-${decision}`,
        root,
      });
      expect(result).toMatchObject({ exitCode: DEMO_EXIT.ok });
      expect(result.journal.state).toBe("terminal");
      const expectedHash = result.journal.resources.find(
        (resource) => resource.kind === "local_database",
      )?.expectedHash;
      expect(expectedHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(await semanticDatabaseHash(result.journal.databasePath)).toBe(
        expectedHash,
      );
      const reopened = createLibSqlOperationalStore({
        url: pathToFileURL(result.journal.databasePath).href,
      });
      const marker = await reopened.execute({
        sql: `SELECT
          (SELECT status FROM incidents WHERE id = ?) AS incident_status,
          (SELECT status FROM workflow_runs WHERE run_id = ?) AS workflow_status`,
        args: [result.journal.incidentId!, result.journal.workflowRunId!],
      });
      reopened.close();
      expect(marker.rows[0]?.workflow_status).toBe("completed");
      expect(marker.rows[0]?.incident_status).toBe("closed");
      expect((await cleanupDemo(root, result.journal.demoRunId)).state).toBe(
        "cleaned",
      );
    },
    30_000,
  );

  it.each(["privilege", "country", "device"] as const)(
    "runs %s through the signed webhook and shared ingestion workflow",
    async (scenario) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-demo-"));
      roots.push(root);
      const result = await runMockDemo({
        scenario,
        runKey: `phase9-${scenario}-key`,
        root,
      });
      expect(result.exitCode).toBe(DEMO_EXIT.ok);
      expect(result.journal.state).toBe("awaiting_approval");
      expect(result.journal.incidentId).toMatch(/^[-a-z0-9_]+$/u);
      // The worker uses the persisted outbox UUID as the workflow run id;
      // asserting that shape proves this is not the runner's former internal
      // `workflow_*` identifier.
      expect(result.journal.workflowRunId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
      );
      expect(result.journal.approvalId).toBeTruthy();
      expect(result.records.map((record) => record.type)).toEqual([
        "preflight",
        "seed",
        "trigger",
        "state",
        "approval_required",
      ]);
      const rerun = await runMockDemo({
        scenario,
        runKey: `phase9-${scenario}-key`,
        root,
      });
      expect(rerun.journal.revision).toBe(result.journal.revision);
      const cleaned = await cleanupDemo(root, result.journal.demoRunId);
      expect(cleaned.state).toBe("cleaned");
      expect((await cleanupDemo(root, result.journal.demoRunId)).state).toBe(
        "cleaned",
      );
      await expect(access(result.journal.databasePath)).rejects.toBeDefined();
      await expect(
        access(`${result.journal.databasePath}-wal`),
      ).rejects.toBeDefined();
      await expect(
        access(`${result.journal.databasePath}-shm`),
      ).rejects.toBeDefined();
      expect((await inspectDemo(root, result.journal.demoRunId))?.state).toBe(
        "cleaned",
      );
    },
    30_000,
  );

  it("keeps staging hermetic and reports unsupported capabilities", () => {
    expect(preflightDemo({ mode: "production" })).toMatchObject({
      ok: false,
      code: "DEMO_PRODUCTION_BLOCKED",
    });
    expect(preflightDemo({ mode: "staging" })).toMatchObject({
      ok: false,
      code: "DEMO_STAGING_PRECONDITION_FAILED",
      capabilities: {
        network: "blocked",
        require_reauthentication: "unsupported",
        mark_device_for_review: "unsupported",
      },
    });
  });

  it("rejects semantically incomplete staging configuration through the F8 parser", () => {
    expect(
      preflightDemo({
        mode: "staging",
        real: true,
        confirmed: true,
        environment: {
          DEMO_MODE: "staging",
          WEBHOOKS_ENABLED: "true",
          WORKOS_PROVIDER_ENABLED: "true",
          WORKOS_API_KEY: "abcdefgh",
          WORKOS_WEBHOOK_SECRET: "abcdefgh",
          WORKOS_STAGING_ORGANIZATION_ID: "org_abcdefgh",
          WORKOS_STAGING_ALLOWED_USER_IDS: "user_abcdefgh",
          WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "soc_manager",
          IPINFO_PROVIDER_ENABLED: "true",
          IPINFO_TOKEN: "abcdefgh",
          LINEAR_PROVIDER_ENABLED: "true",
          LINEAR_API_KEY: "abcdefgh",
          LINEAR_WORKSPACE_ID: "workspace_abcdefgh",
          LINEAR_TEAM_ID: "team_abcdefgh",
          LINEAR_PROJECT_ID: "project_abcdefgh",
          LINEAR_STATUS_STATE_IDS_JSON: '{"x":"abcdefgh"}',
          LINEAR_SEVERITY_LABEL_IDS_JSON: '{"x":"abcdefgh"}',
          LINEAR_INTERNAL_BASE_URL: "not-a-url",
          UPSTASH_PUBSUB_ENABLED: "true",
          UPSTASH_REDIS_URL: "rediss://example.invalid:6379",
          DEMO_STAGING_TARGET_USER_ID: "user_abcdefgh",
          DEMO_STAGING_TARGET_ROLE: "soc_manager",
        },
      }),
    ).toMatchObject({ ok: false, code: "DEMO_STAGING_PRECONDITION_FAILED" });
  });

  it("binds staging preflight to the exact organization, scenario operation, and target", () => {
    const environment = {
      DEMO_MODE: "staging",
      WEBHOOKS_ENABLED: "true",
      WORKOS_PROVIDER_ENABLED: "true",
      WORKOS_API_KEY: "fake-workos-api-key",
      WORKOS_WEBHOOK_SECRET: "fake-workos-webhook-secret",
      WORKOS_STAGING_ORGANIZATION_ID: "org_allowed",
      WORKOS_STAGING_ALLOWED_USER_IDS: "user_allowed",
      WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "soc_manager",
      IPINFO_PROVIDER_ENABLED: "true",
      IPINFO_TOKEN: "fake-ipinfo-token",
      GEOIP_CACHE_HMAC_KEY: Buffer.alloc(32, 7).toString("base64"),
      GEOIP_CACHE_HMAC_KEY_VERSION: "v1",
      LINEAR_PROVIDER_ENABLED: "true",
      LINEAR_API_KEY: "fake-linear-api-key",
      LINEAR_WORKSPACE_ID: "workspace_allowed",
      LINEAR_TEAM_ID: "team_allowed",
      LINEAR_PROJECT_ID: "project_allowed",
      LINEAR_STATUS_STATE_IDS_JSON:
        '{"received":"state_received","investigating":"state_investigating","awaiting_approval":"state_awaiting","approved":"state_approved","rejected":"state_rejected","containing":"state_containing","contained":"state_contained","failed":"state_failed","closed":"state_closed"}',
      LINEAR_SEVERITY_LABEL_IDS_JSON:
        '{"low":"label_low","medium":"label_medium","high":"label_high","critical":"label_critical"}',
      LINEAR_INTERNAL_BASE_URL: "https://linear.example.test",
      UPSTASH_PUBSUB_ENABLED: "true",
      UPSTASH_REDIS_URL: "rediss://example.test:6379",
      DEMO_STAGING_TARGET_ORGANIZATION_ID: "org_unallowlisted",
      DEMO_STAGING_TARGET_USER_ID: "user_allowed",
      DEMO_STAGING_TARGET_ROLE: "soc_manager",
      DEMO_STAGING_TARGET_SESSION_ID: "session_allowed",
      DEMO_STAGING_OPERATION: "restore_previous_role",
    };
    expect(
      preflightDemo({
        mode: "staging",
        real: true,
        confirmed: true,
        scenario: "privilege",
        environment,
      }),
    ).toMatchObject({ ok: false, code: "DEMO_STAGING_PRECONDITION_FAILED" });
    expect(
      preflightDemo({ mode: "mock", real: true, scenario: "privilege" }),
    ).toMatchObject({ ok: false, code: "DEMO_MOCK_CONSENT_FLAGS_INVALID" });
    expect(
      preflightDemo({
        mode: "staging",
        real: true,
        confirmed: true,
        scenario: "device",
        environment: {
          ...environment,
          DEMO_STAGING_TARGET_ORGANIZATION_ID: "org_allowed",
          DEMO_STAGING_OPERATION: "revoke_session",
          DEMO_STAGING_TARGET_DEVICE_ID: "device_allowed",
          DEMO_STAGING_ALLOWED_DEVICE_IDS: "device_allowed",
          // Intentionally no session target/allowlist: revoke_session cannot
          // borrow the device target merely because the scenario is device.
        },
      }),
    ).toMatchObject({ ok: false, code: "DEMO_STAGING_PRECONDITION_FAILED" });
  });

  it("keeps CLI usage and lookup exits mapped to their closed reason families", async () => {
    const invoke = async (...args: string[]) => invokeDemo(...args);
    await expect(
      invoke("preflight", "--scenario", "nope", "--mode", "mock"),
    ).rejects.toMatchObject({ code: DEMO_EXIT.usage });
    try {
      await invoke("inspect", "--demo-run-id", "demo_aaaaaaaaaaaaaaaaaaaaaaaa");
      throw new Error("expected inspect to fail");
    } catch (error) {
      const failed = error as { code?: number; stdout?: string };
      expect(failed.code).toBe(DEMO_EXIT.cleanup);
      expect(JSON.parse(failed.stdout ?? "{}")).toMatchObject({
        type: "error",
        demoRunId: "demo_aaaaaaaaaaaaaaaaaaaaaaaa",
        scenario: null,
        mode: null,
        code: "DEMO_RUN_NOT_FOUND",
      });
    }
    try {
      await invoke("inspect", "--demo-run-id", "bad");
      throw new Error("expected inspect to reject invalid id");
    } catch (error) {
      const failed = error as { code?: number; stdout?: string };
      expect(failed.code).toBe(DEMO_EXIT.usage);
      expect(JSON.parse(failed.stdout ?? "{}")).toMatchObject({
        type: "error",
        code: "DEMO_RUN_ID_INVALID",
      });
    }
  });

  it("fails closed for a tampered F9 device baseline and consumes a nonce only once across instances", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-device-authority-"));
    roots.push(root);
    const result = await runMockDemo({
      scenario: "device",
      runKey: "phase9-device-authority-key",
      root,
    });
    const store = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    const alert = await store.execute({
      sql: "SELECT tenant_id, subject_id FROM incidents WHERE id = ?",
      args: [result.journal.incidentId!],
    });
    const authorityInput = {
      tenantId: String(alert.rows[0]?.tenant_id),
      incidentId: result.journal.incidentId!,
      subjectId: String(alert.rows[0]?.subject_id),
      workflowRunId: result.journal.workflowRunId!,
      incidentKind: "unknown_device_login" as const,
      occurredAt: "2026-08-29T12:00:00.000Z",
      sessionId: "session_unused",
      deviceId: JSON.parse(
        String(
          (
            await store.execute({
              sql: "SELECT canonical_json FROM alerts WHERE incident_id = ?",
              args: [result.journal.incidentId!],
            })
          ).rows[0]?.canonical_json,
        ),
      ).deviceId as string,
    };
    await store.execute({
      sql: "DELETE FROM consumer_effect_ledger WHERE consumer_group = 'phase9-device-nonce'",
    });
    store.close();
    const provider = () =>
      new MockEndpointEvidenceProvider({
        requireDemoBaseline: true,
        openBaselineStore: () =>
          createLibSqlOperationalStore({
            url: pathToFileURL(result.journal.databasePath).href,
          }),
      });
    const first = await provider().inspect(authorityInput, {
      signal: new AbortController().signal,
      attempt: 1,
    });
    const second = await provider().inspect(authorityInput, {
      signal: new AbortController().signal,
      attempt: 1,
    });
    expect(first.status).toBe("success");
    expect(second.status).toBe("success");
    if (first.status === "success" && second.status === "success") {
      expect(
        first.facts.find((fact) => fact.factType === "device.signatureValid")
          ?.value,
      ).toBe(true);
      expect(
        second.facts.find((fact) => fact.factType === "device.signatureValid")
          ?.value,
      ).toBe(false);
    }
    const tamper = createLibSqlOperationalStore({
      url: pathToFileURL(result.journal.databasePath).href,
    });
    await tamper.execute({
      sql: "UPDATE identity_snapshots SET integrity_hash = ? WHERE incident_id = ?",
      args: ["0".repeat(64), result.journal.incidentId!],
    });
    tamper.close();
    const corrupted = await provider().inspect(authorityInput, {
      signal: new AbortController().signal,
      attempt: 1,
    });
    expect(corrupted).toMatchObject({
      status: "invalid_response",
      error: { code: "INVALID_RESPONSE" },
    });
  });

  it.each([
    ["privilege", "approve"],
    ["country", "reject"],
    ["device", "approve"],
  ] as const)(
    "uses the existing mock approval authority for %s (%s)",
    async (scenario, decision) => {
      const root = await mkdtemp(join(tmpdir(), "phase9-decision-"));
      roots.push(root);
      const result = await runMockDemo({
        scenario,
        decision,
        runKey: `phase9-${scenario}-${decision}-key`,
        root,
      });
      expect(result.exitCode).toBe(DEMO_EXIT.ok);
      expect(result.journal.state).toBe("terminal");
      expect(result.records.map((record) => record.type)).toContain("terminal");
      expect(result.records.map((record) => record.type)).toContain(
        "verification",
      );
    },
    30_000,
  );

  it("enforces the read-only store allowlist for CTEs, comments, batches, and transactions", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase9-read-only-store-"));
    roots.push(root);
    const databasePath = join(root, "read-only.db");
    const writable = createLibSqlOperationalStore({
      url: pathToFileURL(databasePath).href,
    });
    await writable.execute({ sql: "CREATE TABLE probe (value INTEGER)" });
    await writable.execute({ sql: "INSERT INTO probe(value) VALUES (1)" });
    const readOnly = createReadOnlyLibSqlOperationalStore({
      url: pathToFileURL(databasePath).href,
    });
    await expect(
      readOnly.execute({
        sql: " /* harmless comment */ WITH x AS (SELECT 1) SELECT * FROM x",
      }),
    ).resolves.toMatchObject({ rows: [{ "1": 1 }] });
    for (const sql of [
      "WITH x AS (SELECT 1) DELETE FROM probe",
      "WITH x AS (SELECT 1) UPDATE probe SET value = 2",
      "WITH x AS (SELECT 1) INSERT INTO probe(value) VALUES (2)",
      "WITH x AS (SELECT 1) REPLACE INTO probe(value) VALUES (2)",
      "WITH x AS (UPDATE probe SET value = 2 RETURNING value) SELECT * FROM x",
      "WITH x AS (SELECT 1) PRAGMA user_version = 1",
      "/* leading comment */ DELETE FROM probe",
      "CREATE TABLE probe_two (value INTEGER)",
      "BEGIN IMMEDIATE",
      "SELECT value FROM probe; DELETE FROM probe",
    ])
      await expect(readOnly.execute({ sql })).rejects.toThrow(
        "Storage is temporarily unavailable",
      );
    await expect(
      readOnly.transaction((tx) =>
        tx.batch([
          { sql: "SELECT value FROM probe" },
          { sql: "WITH x AS (SELECT 1) DELETE FROM probe" },
        ]),
      ),
    ).rejects.toThrow("Storage is temporarily unavailable");
    readOnly.close();
    await expect(
      writable.execute({ sql: "SELECT value FROM probe ORDER BY value" }),
    ).resolves.toMatchObject({ rows: [{ value: 1 }] });
    writable.close();
  });
});
