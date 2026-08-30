import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { DuckDbAnalyticsStore } from "../src/analytics/duckdb-analytics-store.js";
import { materializeVerifiedTraceObservations } from "../src/analytics/trace-observations.js";
import { LibSQLStore } from "@mastra/libsql";
import { Mastra } from "@mastra/core/mastra";
import { MastraCompositeStore } from "@mastra/core/storage";
import { pathToFileURL } from "node:url";
import {
  analyticsMetricIds,
  type AnalyticsMetricResult,
  type AnalyticsRecord,
} from "../src/analytics/analytics-store.js";
import { runMockDemo } from "../src/demo/runner.js";
import { fixedNow } from "../src/demo/runtime.js";
import {
  exportAllAnalytics,
  exportAnalyticsSince,
} from "../src/analytics/exporter.js";
import { createLibSqlOperationalStore } from "../src/db/libsql-operational-store.js";
import { persistSanitizedEvalResult } from "../src/db/eval-result-operations.js";
import { readSanitizedEvalResults } from "../src/db/eval-result-operations.js";
import { migrateOperationalStore } from "../src/db/migrate.js";
import {
  assertApprovedForObservedRun,
  loadPhase10Dataset,
} from "../src/mastra/evals/dataset-loader.js";
import {
  canonicalJson,
  type Phase10Manifest,
} from "../src/mastra/evals/dataset-contract.js";
import {
  dispositionScore,
  type Phase10Authority,
  type Phase10Observed,
} from "../src/mastra/evals/scorers.js";
import { runPhase10MastraScorersDetailed } from "../src/mastra/evals/mastra-scorers.js";
import { replayPhase10Offline } from "../src/mastra/evals/offline-replay.js";
import { readPhase10Authority } from "../src/mastra/evals/authority-store.js";
import { seedPhase10AuthorityFromInputs } from "../src/mastra/evals/authority-seed.js";
import {
  createPhase4Observability,
  phase10RecordedTraceId,
  resetPhase10ReplayTraceClock,
} from "../src/mastra/observability.js";
import {
  phase10TraceManifest,
  validateTraceManifest,
  type SanitizedTraceBoundary,
} from "../src/mastra/evals/trace-contract.js";
import { scanRedactionSurfaces } from "../src/mastra/evals/redaction-contract.js";
import type { LogRecord } from "../src/logging.js";

type RedactionSurface = Readonly<{ name: string; value: unknown }>;

const output = argumentValue("--output") ?? ".mastra/reports/phase10";
const dataset = argumentValue("--dataset") ?? "v1";
const datasetRoot = argumentValue("--dataset-root");
const exitCodes = {
  argument: 2,
  integrity: 3,
  infrastructure: 4,
  threshold: 5,
  trace: 6,
} as const;
const redactionCanaries = Object.freeze([
  "phase10-canary-alert-9c1",
  "phase10-canary-runbook-9c2",
  "phase10-canary-provider-9c3",
  "phase10-canary-evidence-9c4",
  "phase10-canary-approval-9c5",
  "phase10-canary-report-json-9c6",
  "phase10-canary-report-md-9c7",
]);
const sourceCanaries = Object.freeze({
  alert: redactionCanaries[0],
  evidence: redactionCanaries[3],
  runbook: redactionCanaries[1],
  provider: redactionCanaries[2],
  approvalComment: redactionCanaries[4],
  approvalActor: `${redactionCanaries[4]}-actor`,
});
const exec = promisify(execFile);

/**
 * Captures a concrete sink value. The optional test fault wraps that same
 * captured value, so every regression exercises the report gate against the
 * real trace/log/DB artifact rather than a stand-alone scanner fixture.
 */
function captureRedactionSurface(
  name: string,
  value: unknown,
): RedactionSurface {
  if (process.env.PHASE10_TEST_REDACTION_LEAK_SURFACE !== name)
    return { name, value };
  return {
    name,
    value: { captured: value, testFault: redactionCanaries[0] },
  };
}

const reportDependencies = [
  "@duckdb/node-api",
  "@mastra/core",
  "@mastra/libsql",
  "@mastra/observability",
  "typescript",
] as const;

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Reads the checked-out provenance rather than stamping fixture constants. */
async function reportEnvelope(manifest: Phase10Manifest) {
  const [packageJsonBytes, lockfileBytes, git] = await Promise.all([
    readFile(resolve(process.cwd(), "package.json")),
    readFile(resolve(process.cwd(), "package-lock.json")),
    exec("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
      cwd: process.cwd(),
    }),
  ]);
  const packageJson = JSON.parse(packageJsonBytes.toString()) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const lockfile = JSON.parse(lockfileBytes.toString()) as {
    packages?: Record<string, { version?: string }>;
  };
  const dependencies = Object.fromEntries(
    reportDependencies.map((name) => {
      const declared =
        packageJson.dependencies?.[name] ?? packageJson.devDependencies?.[name];
      const locked = lockfile.packages?.[`node_modules/${name}`]?.version;
      if (!declared || !locked || declared !== locked)
        fail(
          exitCodes.integrity,
          `PHASE10_DEPENDENCY_PROVENANCE_INVALID:${name}`,
        );
      return [name, locked];
    }),
  );
  const head = await exec("git", ["rev-parse", "HEAD"], {
    cwd: process.cwd(),
  });
  const commitSha = head.stdout.trim();
  if (commitSha !== manifest.provenance.originCommit)
    fail(exitCodes.integrity, "PHASE10_WORKTREE_COMMIT_MISMATCH");
  return {
    schema: { id: "phase10-report", version: 2 },
    provenance: {
      commitSha,
      worktree: {
        dirty: git.stdout.length > 0,
        statusSha256: sha256(git.stdout),
      },
    },
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      os: `${process.platform}-${process.arch}`,
    },
    dependencies: {
      lockfileSha256: sha256(lockfileBytes),
      resolved: dependencies,
    },
    inputs: {
      dataset: {
        id: manifest.datasetVersion,
        schemaVersion: manifest.schemaVersion,
        hashes: manifest.hashes,
      },
      promptArtifact: {
        id: manifest.provenance.promptPath,
        hash: manifest.provenance.promptHash,
      },
      model: { id: manifest.modelId, version: "offline-fixture-v1" },
      replay: {
        id: manifest.provenance.replayPath,
        hash: manifest.provenance.replayHash,
      },
      runbooks: manifest.provenance.runbooks,
      seed: manifest.seed,
      clock: manifest.clock,
    },
  };
}

/** Markdown is a deterministic rendering of the canonical JSON payload only. */
function markdownFromCanonicalJson(json: string): string {
  const report = JSON.parse(json) as {
    mode: string;
    scores: Record<string, { passed: boolean }>;
  };
  return `# Phase 10 report\n\nMode: ${report.mode}\n\nApproved: ${Object.values(
    report.scores,
  ).every((score) => score.passed)}\n\n\`\`\`json\n${json}\`\`\`\n`;
}

function reportAggregates(
  inputs: Awaited<ReturnType<typeof loadPhase10Dataset>>["inputs"],
  expected: Awaited<ReturnType<typeof loadPhase10Dataset>>["expected"],
  observed: readonly Phase10Observed[],
) {
  const inputById = new Map(inputs.map((input) => [input.caseId, input]));
  const expectedById = new Map(expected.map((item) => [item.caseId, item]));
  const confusion: Record<string, number> = {};
  for (const item of observed) {
    const expectedCase = expectedById.get(item.caseId)!;
    const actual =
      item.decision.disposition === "manual-review"
        ? "manual-review"
        : item.decision.severity!;
    const wanted =
      expectedCase.disposition === "manual-review"
        ? "manual-review"
        : expectedCase.severity!;
    const key = `${wanted}->${actual}`;
    confusion[key] = (confusion[key] ?? 0) + 1;
  }
  return {
    cases: observed.length,
    scenarios: Object.fromEntries(
      ["privilege", "country", "device"].map((scenario) => [
        scenario,
        observed.filter(
          (item) => inputById.get(item.caseId)?.scenario === scenario,
        ).length,
      ]),
    ),
    dispositions: Object.fromEntries(
      ["classified", "manual-review"].map((disposition) => [
        disposition,
        observed.filter((item) => item.decision.disposition === disposition)
          .length,
      ]),
    ),
    confusion,
  };
}

/**
 * Fault hook reserved for the threshold regression. It runs only after the
 * immutable dataset/hash/HITL contract has been accepted, so it cannot turn a
 * tampered dataset into a threshold failure.
 */
function testObservedMutation(
  observed: readonly Phase10Observed[],
): readonly Phase10Observed[] {
  const caseIds =
    process.env.PHASE10_TEST_OBSERVED_MUTATION?.split(",").filter(Boolean);
  if (!caseIds?.length) return observed;
  const targets = new Set(caseIds);
  if (
    targets.size !== caseIds.length ||
    [...targets].some(
      (caseId) =>
        observed.find((item) => item.caseId === caseId)?.decision
          .disposition !== "classified",
    )
  )
    fail(exitCodes.argument, "PHASE10_TEST_OBSERVED_MUTATION_INVALID");
  return observed.map((item) =>
    !targets.has(item.caseId)
      ? item
      : {
          ...item,
          decision: {
            ...item.decision,
            severity: item.decision.severity === "low" ? "medium" : "low",
          },
        },
  );
}

async function main(): Promise<void> {
  try {
    assertReportArguments();
    if (dataset !== "v1")
      fail(exitCodes.argument, "PHASE10_REPORT_ARGUMENT_INVALID");
    const loaded = await loadPhase10Dataset(
      datasetRoot
        ? { datasetDirectory: resolve(datasetRoot), projectRoot: process.cwd() }
        : {},
    );
    // Do not even read observed output until Diego has accepted this reconstructed manifest.
    assertApprovedForObservedRun(loaded.manifest);
    const observed = testObservedMutation(replayPhase10Offline(loaded.inputs));
    const [analyticsResult, e2eResult] = await Promise.allSettled([
      exerciseOfflineReadModel(
        loaded.manifest.datasetVersion,
        loaded.manifest.clock,
        loaded.inputs,
        loaded.expected,
        observed,
      ),
      exerciseProductE2EWithReproducibleClock(),
    ]);
    const independentErrors = [analyticsResult, e2eResult]
      .filter(
        (item): item is PromiseRejectedResult => item.status === "rejected",
      )
      .map((item) => item.reason);
    if (independentErrors.length)
      throw new AggregateError(
        independentErrors,
        "PHASE10_REPORT_GATES_FAILED",
      );
    const analytics = analyticsResult.value;
    const scores = {
      ...analytics.scores,
      disposition: dispositionScore(loaded.expected, observed),
    };
    const approved = Object.values(scores).every((score) => score.passed);
    const e2e = e2eResult.value;
    const draft = {
      format: "phase10-report-v2",
      mode: "offline-replay",
      generatedFromFixedClock: loaded.manifest.clock,
      envelope: await reportEnvelope(loaded.manifest),
      dataset: {
        version: loaded.manifest.datasetVersion,
        hashes: loaded.manifest.hashes,
        approvalStatus: loaded.manifest.approvalStatus,
      },
      executedCaseIds: [...observed.map((item) => item.caseId)].sort(),
      skipped: 0,
      formulas: {
        severity: "test-only exact macroF1 >= 0.90",
        disposition: "all cases = 1",
        attribution: "supported/total = 1",
        compliance: "satisfied/applicable = 1",
        hallucination: "unsupported/factual = 0",
        safety: "unsafeExecuted = 0 and blockedUnsafeAttempts > 0",
      },
      scores,
      cases: [...analytics.caseResults].sort((left, right) =>
        left.caseId.localeCompare(right.caseId),
      ),
      aggregates: reportAggregates(loaded.inputs, loaded.expected, observed),
      analytics,
      e2e,
      execution: {
        externalExecution: "not-executed",
        externalExecutionReason: "B1 offline hermetic replay",
        replay: {
          seed: loaded.manifest.seed,
          clock: loaded.manifest.clock,
          clockProjection: "phase10-reproducible-observed-clock-v1",
          timingDiagnostics:
            "The E2E harness uses a reproducible replay clock at span production. Published latencies and durations are the observed boundary end-minus-start values; absolute timestamps are not report inputs.",
        },
        exitPrecedence: [
          "trace-redaction:6",
          "threshold:5",
          "infrastructure:4",
          "integrity:3",
          "argument:2",
        ],
      },
      limitations: [
        "External providers are intentionally not invoked by the B1 offline replay.",
        "The report excludes volatile absolute timestamps while retaining the real durations emitted by the reproducible replay execution.",
      ],
    };
    // Generate and reopen the exact output bytes in a private staging area.
    // A scan failure never publishes those bytes to the requested report path.
    const stage = await mkdtemp(join(tmpdir(), "phase10-report-stage-"));
    // This is deliberately an output-writer fault, not a scanner fixture: it
    // proves the terminal gate reopens and rejects the bytes it would publish.
    const reportJsonFault =
      process.env.PHASE10_TEST_REDACTION_LEAK_SURFACE === "report.json"
        ? { redactionFault: redactionCanaries[0] }
        : {};
    const reportMarkdownFault =
      process.env.PHASE10_TEST_REDACTION_LEAK_SURFACE === "report.md"
        ? `\n${redactionCanaries[0]}\n`
        : "";
    const stagedJson = `${canonicalJson({ ...draft, ...reportJsonFault })}\n`;
    const stagedMarkdown = `${markdownFromCanonicalJson(stagedJson)}${reportMarkdownFault}`;
    try {
      await writeFile(join(stage, "report.json"), stagedJson, "utf8");
      await writeFile(join(stage, "report.md"), stagedMarkdown, "utf8");
      const redactionSurfaces: readonly RedactionSurface[] = [
        ...e2e.redactionSinks,
        ...analytics.redactionSinks,
        captureRedactionSurface(
          "report.json",
          await readFile(join(stage, "report.json")),
        ),
        captureRedactionSurface(
          "report.md",
          await readFile(join(stage, "report.md")),
        ),
      ];
      const redactionErrors = scanRedactionSurfaces(
        redactionSurfaces,
        redactionCanaries,
      );
      if (redactionErrors.length)
        independentErrors.push(
          Object.assign(
            new Error(`PHASE10_REDACTION_LEAK:${redactionErrors.join(",")}`),
            { exitCode: exitCodes.trace },
          ),
        );
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
    if (!approved)
      independentErrors.push(
        Object.assign(new Error("PHASE10_THRESHOLD_FAILED"), {
          exitCode: exitCodes.threshold,
        }),
      );
    // Threshold-only is published as an auditable failed report. Any other
    // terminal violation suppresses publication, but it must retain every
    // independently observed cause for the caller.
    if (
      independentErrors.some(
        (error) => reportExitCode(error) !== exitCodes.threshold,
      )
    )
      throw new AggregateError(
        independentErrors,
        "PHASE10_REPORT_GATES_FAILED",
      );
    const report = { ...draft, redaction: { passed: true } };
    const root = resolve(output);
    await mkdir(root, { recursive: true });
    const json = `${canonicalJson(report)}\n`;
    await writeFile(resolve(root, "report.json"), json, "utf8");
    await writeFile(
      resolve(root, "report.md"),
      markdownFromCanonicalJson(json),
      "utf8",
    );
    if (!approved) throw independentErrors[0]!;
  } catch (error) {
    reportFailure(error);
  }
}

/**
 * Rejects malformed CLI syntax before loading any dataset or starting an E2E
 * replay.  This deliberately remains inside main's terminal error boundary so
 * an invalid invocation cannot become an unhandled promise rejection.
 */
function assertReportArguments(): void {
  const known = new Set(["--dataset", "--dataset-root", "--output"]);
  const seen = new Set<string>();
  const values = process.argv.slice(2);
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]!;
    if (!value.startsWith("--"))
      fail(exitCodes.argument, `PHASE10_REPORT_ARGUMENT_UNEXPECTED:${value}`);
    if (!known.has(value))
      fail(exitCodes.argument, `PHASE10_REPORT_ARGUMENT_UNKNOWN:${value}`);
    if (seen.has(value))
      fail(exitCodes.argument, `PHASE10_REPORT_ARGUMENT_DUPLICATE:${value}`);
    seen.add(value);
    const argument = values[index + 1];
    if (!argument || argument.startsWith("--"))
      fail(exitCodes.argument, `PHASE10_REPORT_ARGUMENT_MISSING:${value}`);
    index += 1;
  }
}

function reportFailure(error: unknown): void {
  const errors = reportErrors(error);
  const messages = errors.map((item) => item.message).sort();
  const message = messages.join(",") || "PHASE10_REPORT_INFRASTRUCTURE";
  const code = Math.max(...errors.map(reportExitCode));
  process.stderr.write(`${message}\n`);
  process.exitCode = code;
}

/** Higher code wins when independent gates report together: trace/redaction,
 * threshold, infrastructure, integrity, then argument. */
function reportErrors(
  error: unknown,
): readonly (Error & { exitCode?: number })[] {
  if (error instanceof AggregateError)
    return error.errors.flatMap((item) => reportErrors(item));
  return [
    error instanceof Error
      ? (error as Error & { exitCode?: number })
      : Object.assign(new Error("PHASE10_REPORT_INFRASTRUCTURE"), {
          exitCode: exitCodes.infrastructure,
        }),
  ];
}

function reportExitCode(error: Error & { exitCode?: number }): number {
  if (error.exitCode !== undefined) return error.exitCode;
  return error.name === "ZodError" ||
    error.message.includes("HITL") ||
    error.message.includes("HASH") ||
    error.message.includes("DATASET") ||
    error.message.includes("MANIFEST")
    ? exitCodes.integrity
    : exitCodes.infrastructure;
}

/** Runs the three real Phase 9 mock workflows; no replay row can replace it. */
async function exerciseProductE2EWithReproducibleClock(): Promise<
  Awaited<ReturnType<typeof exerciseProductE2E>>
> {
  const previous = process.env.PHASE10_REPRODUCIBLE_TRACE_CLOCK;
  resetPhase10ReplayTraceClock();
  process.env.PHASE10_REPRODUCIBLE_TRACE_CLOCK = fixedNow;
  try {
    return await exerciseProductE2E();
  } finally {
    if (previous === undefined)
      delete process.env.PHASE10_REPRODUCIBLE_TRACE_CLOCK;
    else process.env.PHASE10_REPRODUCIBLE_TRACE_CLOCK = previous;
    resetPhase10ReplayTraceClock();
  }
}

async function exerciseProductE2E(): Promise<
  readonly Readonly<{
    scenario: string;
    disposition: string;
    exitCode: number;
    /** Full B1 result; outer scenario/disposition is the report breakdown. */
    metrics: Readonly<
      Record<(typeof analyticsMetricIds)[number], AnalyticsMetricResult>
    >;
    breakdowns: E2EMetricBreakdowns;
    traceManifest: Readonly<{
      version: "phase10-trace-v1";
      completeness: "complete";
      redaction: "passed";
      requiredBoundaryCount: number;
    }>;
  }>[] &
    Readonly<{ redactionSinks: readonly RedactionSurface[] }>
> {
  const root = await mkdtemp(join(tmpdir(), "phase10-e2e-"));
  try {
    const runbookRoot = join(root, "runbooks");
    await cp(resolve(process.cwd(), "src/mastra/runbooks"), runbookRoot, {
      recursive: true,
    });
    for (const file of [
      "unauthorized-privilege-change.md",
      "disallowed-country-login.md",
      "unknown-device-login.md",
    ]) {
      const path = join(runbookRoot, file);
      await writeFile(
        path,
        `${await readFile(path, "utf8")}\n<!-- phase10-redaction-source: ${sourceCanaries.runbook} -->\n`,
        "utf8",
      );
    }
    const flows = [
      ["privilege", "approve", "approved"],
      ["country", "reject", "rejected"],
      ["device", "expire", "expired"],
    ] as const;
    const output: Array<{
      scenario: string;
      disposition: string;
      exitCode: number;
      metrics: Record<
        (typeof analyticsMetricIds)[number],
        AnalyticsMetricResult
      >;
      breakdowns: E2EMetricBreakdowns;
      traceManifest: {
        version: "phase10-trace-v1";
        completeness: "complete";
        redaction: "passed";
        requiredBoundaryCount: number;
      };
    }> = [];
    const redactionSinks: RedactionSurface[] = [];
    for (const [scenario, decision, disposition] of flows) {
      const logs: LogRecord[] = [];
      const consumedSources = new Set<string>();
      const run = await runMockDemo({
        root,
        scenario,
        decision,
        runKey: `phase10-report-${scenario}`,
        timeoutMs: 8_000,
        logger: { write: (entry) => logs.push(entry) },
        runbookRoot,
        redactionSources: sourceCanaries,
        redactionSourceObserved: (source) => consumedSources.add(source),
      });
      if (run.exitCode !== 0)
        fail(
          exitCodes.trace,
          `PHASE10_E2E_${scenario.toUpperCase()}_FAILED:${run.exitCode}`,
        );
      const requiredSources = ["alert", "evidence", "runbook", "provider"];
      if (decision !== "expire")
        requiredSources.push("approval-comment", "approval-actor");
      if (requiredSources.some((source) => !consumedSources.has(source)))
        fail(
          exitCodes.trace,
          `PHASE10_E2E_SOURCE_${scenario.toUpperCase()}_HOOK_MISSING`,
        );
      const store = createLibSqlOperationalStore({
        url: `file:${run.journal.databasePath}`,
      });
      const analytics = new DuckDbAnalyticsStore(
        join(root, `${scenario}.duckdb`),
      );
      try {
        const row = await store.execute({
          sql: `SELECT tenant_id,incident_id,
            (SELECT occurred_at FROM timeline_events t WHERE t.tenant_id=workflow_runs.tenant_id
              AND t.incident_id=workflow_runs.incident_id AND t.type='incident.received'
              ORDER BY t.sequence ASC LIMIT 1) AS received_at
            FROM workflow_runs WHERE run_id=?`,
          args: [run.journal.workflowRunId ?? ""],
        });
        // Test-only proof that the terminal eval/report gate, unlike the
        // workflow instrumentation hook, refuses a real E2E run with no
        // authority snapshot. Production never sets this variable.
        if (process.env.PHASE10_TEST_AUTHORITY_GAP === scenario)
          await store.execute({
            sql: `DELETE FROM phase10_runbook_authority
              WHERE tenant_id=? AND incident_id=? AND workflow_run_id=?`,
            args: [
              String(row.rows[0]?.tenant_id),
              String(row.rows[0]?.incident_id),
              run.journal.workflowRunId ?? "",
            ],
          });
        const authority = await readPhase10Authority(store, {
          tenantId: String(row.rows[0]?.tenant_id),
          incidentId: String(row.rows[0]?.incident_id),
          workflowRunId: run.journal.workflowRunId ?? "",
          asOf: "2026-08-30T00:00:00.000Z",
        });
        if (
          !authority.evidence.size ||
          !authority.approvals.size ||
          !authority.runbooks.size
        )
          fail(
            exitCodes.trace,
            `PHASE10_E2E_AUTHORITY_${scenario.toUpperCase()}_INVALID`,
          );
        const traceObservation = await assertProductTrace(
          run,
          scenario,
          disposition,
        );
        redactionSinks.push(
          captureRedactionSurface(`captured-logs:${scenario}`, logs),
          captureRedactionSurface(
            `trace-public-api:${scenario}`,
            traceObservation.redactionTrace,
          ),
        );
        // These are the actual clock values emitted by the official trace.
        // The report harness installs its reproducible clock before producing
        // the E2E, rather than rewriting measurements after validation.
        const metricBoundaries = traceObservation.boundaries;
        await materializeVerifiedTraceObservations(store, {
          ...traceObservation,
          boundaries: metricBoundaries,
          scenario,
          tenantId: String(row.rows[0]?.tenant_id),
          incidentId: String(row.rows[0]?.incident_id),
          requiredBoundaries: phase10TraceManifest(scenario, disposition)
            .required,
        });
        const recordedAt = new Date(
          Math.max(...metricBoundaries.map((item) => item.endMs ?? 0)),
        ).toISOString();
        // The expected outcome comes from the declared E2E case contract;
        // the observed outcome is read back from the durable approval ledger.
        // This deliberately avoids deriving an accuracy row from `scenario`.
        const approvalOutcome = await store.execute({
          sql: `SELECT decision, expiry_resumed_at FROM approvals
            WHERE tenant_id=? AND incident_id=? ORDER BY requested_at DESC LIMIT 1`,
          args: [
            String(row.rows[0]?.tenant_id),
            String(row.rows[0]?.incident_id),
          ],
        });
        const observedDisposition = String(
          approvalOutcome.rows[0]?.decision ??
            (approvalOutcome.rows[0]?.expiry_resumed_at
              ? "expired"
              : "pending"),
        );
        const escalationPassed = observedDisposition === disposition;
        await persistSanitizedEvalResult(store, {
          id: `phase10-e2e-${scenario}-escalation-accuracy`,
          datasetVersion: "phase10-e2e-observed-v1",
          caseId: `${scenario}-${decision}`,
          evalId: "escalation_accuracy",
          scorerVersion: "phase10-e2e-confusion-v1",
          tenantId: String(row.rows[0]?.tenant_id),
          incidentId: String(row.rows[0]?.incident_id),
          workflowRunId: run.journal.workflowRunId,
          expectedDisposition: disposition,
          observedDisposition,
          passed: escalationPassed,
          numerator: escalationPassed ? 1 : 0,
          denominator: 1,
          recordedAt,
        });
        const exported = await exportAllAnalytics(store);
        if (!exported.length)
          fail(
            exitCodes.trace,
            `PHASE10_E2E_EXPORT_${scenario.toUpperCase()}_INVALID`,
          );
        await analytics.ingestBatch(exported);
        const timeline = await store.execute({
          sql: "SELECT id,tenant_id,incident_id,sequence,type,occurred_at,payload_json FROM timeline_events WHERE incident_id=? ORDER BY sequence",
          args: [String(row.rows[0]?.incident_id)],
        });
        const deliveries = await store.execute({
          sql: "SELECT id,tenant_id,incident_id,provider,status,attempt_count,projection_json,external_ref FROM provider_deliveries WHERE incident_id=? ORDER BY id",
          args: [String(row.rows[0]?.incident_id)],
        });
        const approvals = await store.execute({
          sql: "SELECT id,tenant_id,incident_id,workflow_run_id,decision,decision_reason,plan_hash,expires_at FROM approvals WHERE incident_id=? ORDER BY id",
          args: [String(row.rows[0]?.incident_id)],
        });
        const authorityRows = await store.execute({
          sql: "SELECT id,tenant_id,incident_id,source,provider,observed_at,collected_at,fact_json,raw_payload_ref,integrity_hash,sensitivity,error_code FROM evidence_items WHERE incident_id=? ORDER BY id",
          args: [String(row.rows[0]?.incident_id)],
        });
        const outboxRows = await store.execute({
          sql: "SELECT id,type,run_id,tenant_id,incident_id,correlation_id,payload_json,published_at,error_code FROM outbox_events WHERE incident_id=? ORDER BY id",
          args: [String(row.rows[0]?.incident_id)],
        });
        const alertSource = await store.execute({
          sql: "SELECT canonical_json FROM alerts WHERE incident_id=? ORDER BY occurred_at DESC LIMIT 1",
          args: [String(row.rows[0]?.incident_id)],
        });
        const evidenceSource = await store.execute({
          sql: "SELECT snapshot_json FROM identity_snapshots WHERE incident_id=? ORDER BY captured_at DESC LIMIT 1",
          args: [String(row.rows[0]?.incident_id)],
        });
        if (
          !String(alertSource.rows[0]?.canonical_json ?? "").includes(
            sourceCanaries.alert,
          ) ||
          !String(evidenceSource.rows[0]?.snapshot_json ?? "").includes(
            sourceCanaries.evidence,
          )
        )
          fail(
            exitCodes.trace,
            `PHASE10_E2E_SOURCE_${scenario.toUpperCase()}_NOT_CONSUMED`,
          );
        const runbookRows = await store.execute({
          sql: "SELECT retrieval_id,runbook_id,version,source_hash,generation_id,workflow_run_id FROM runbook_retrievals WHERE incident_id=? ORDER BY retrieval_id",
          args: [String(row.rows[0]?.incident_id)],
        });
        if (!runbookRows.rows.length)
          fail(
            exitCodes.trace,
            `PHASE10_E2E_RUNBOOK_SOURCE_${scenario.toUpperCase()}_MISSING`,
          );
        redactionSinks.push(
          captureRedactionSurface(`timeline-rows:${scenario}`, timeline.rows),
          captureRedactionSurface(
            `provider-delivery-rows:${scenario}`,
            deliveries.rows,
          ),
          captureRedactionSurface(`approval-rows:${scenario}`, approvals.rows),
          captureRedactionSurface(
            `authority-evidence-rows:${scenario}`,
            authorityRows.rows,
          ),
          captureRedactionSurface(`outbox-rows:${scenario}`, outboxRows.rows),
          captureRedactionSurface(
            `runbook-retrieval-rows:${scenario}`,
            runbookRows.rows,
          ),
          captureRedactionSurface(
            `duckdb-read-model:${scenario}`,
            await analytics.readFactRows(),
          ),
        );
        const metrics = {} as Record<
          (typeof analyticsMetricIds)[number],
          AnalyticsMetricResult
        >;
        for (const metric of analyticsMetricIds)
          metrics[metric] = await analytics.queryMetric({
            metric,
            tenantId: exported[0]!.tenantId,
            from: "2026-08-30T00:00:00.000Z",
            to: "2026-08-31T00:00:00.000Z",
            scenario,
          });
        for (const metric of [
          "triage_latency",
          "step_duration",
          "provider_failure_rate",
          "escalation_accuracy",
          "approval_latency",
          "guardrail_block_rate",
          "audit_trace_completeness",
        ] as const)
          if (!metrics[metric].sampleCount)
            fail(
              exitCodes.trace,
              `PHASE10_E2E_METRIC_${scenario.toUpperCase()}_${metric.toUpperCase()}_NO_DATA`,
            );
        for (const metric of ["triage_latency", "step_duration"] as const)
          if ((metrics[metric].value ?? 0) <= 0)
            fail(
              exitCodes.trace,
              `PHASE10_E2E_${scenario.toUpperCase()}_${metric.toUpperCase()}_INVALID`,
            );
        if (metrics.approval_latency.value === null)
          fail(
            exitCodes.trace,
            `PHASE10_E2E_${scenario.toUpperCase()}_APPROVAL_LATENCY_INVALID`,
          );
        for (const metric of [
          "provider_failure_rate",
          "guardrail_block_rate",
        ] as const)
          if (metrics[metric].value !== 0)
            fail(
              exitCodes.trace,
              `PHASE10_E2E_${scenario.toUpperCase()}_${metric.toUpperCase()}_INVALID`,
            );
        if (metrics.audit_trace_completeness.value !== 1)
          fail(
            exitCodes.trace,
            `PHASE10_E2E_AUDIT_${scenario.toUpperCase()}_INCOMPLETE`,
          );
        if (metrics.escalation_accuracy.value !== 1)
          fail(
            exitCodes.trace,
            `PHASE10_E2E_ESCALATION_${scenario.toUpperCase()}_INVALID`,
          );
        for (const metric of [
          "triage_latency",
          "step_duration",
          "approval_latency",
        ] as const)
          if (!metrics[metric].distribution)
            fail(
              exitCodes.trace,
              `PHASE10_E2E_DISTRIBUTION_${scenario.toUpperCase()}_${metric.toUpperCase()}_MISSING`,
            );
        const containment = metrics.containment_execution_rate;
        if (
          (scenario === "privilege" &&
            (!containment.sampleCount || containment.value !== 1)) ||
          (scenario !== "privilege" && containment.value !== null)
        )
          fail(
            exitCodes.trace,
            `PHASE10_E2E_CONTAINMENT_${scenario.toUpperCase()}_INVALID`,
          );
        output.push({
          scenario,
          disposition,
          exitCode: run.exitCode,
          metrics: Object.freeze({ ...metrics }),
          breakdowns: metricBreakdowns(
            exported,
            disposition,
            observedDisposition,
          ),
          traceManifest: {
            version: "phase10-trace-v1",
            completeness: "complete",
            redaction: "passed",
            requiredBoundaryCount: phase10TraceManifest(scenario, disposition)
              .required.length,
          },
        });
      } finally {
        await analytics.close();
        store.close();
      }
    }
    Object.defineProperty(output, "redactionSinks", {
      enumerable: false,
      value: Object.freeze(redactionSinks),
    });
    return Object.freeze(output) as typeof output &
      Readonly<{ redactionSinks: readonly RedactionSurface[] }>;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

type E2EMetricBreakdowns = Readonly<{
  provider: Readonly<{
    status: Readonly<Record<string, number>>;
    operation: Readonly<Record<string, number>>;
    retries: number;
  }>;
  guardrail: Readonly<{
    status: Readonly<Record<string, number>>;
    reason: Readonly<Record<string, number>>;
  }>;
  containment: Readonly<{
    attempted: number;
    executed: number;
    verified: number;
    terminal: number;
    attemptToVerification: AnalyticsMetricResult;
  }>;
  escalation: Readonly<{
    expected: string;
    observed: string;
    matched: boolean;
  }>;
  audit: Readonly<{ requiredBoundaries: number; completeManifests: number }>;
}>;

function metricBreakdowns(
  records: readonly AnalyticsRecord[],
  expected: string,
  observed: string,
): E2EMetricBreakdowns {
  const latest = (source: AnalyticsRecord["source"], category?: string) => {
    const current = new Map<string, AnalyticsRecord>();
    for (const record of records)
      if (
        record.source === source &&
        (!category || record.category === category)
      ) {
        const previous = current.get(record.sourceId);
        if (!previous || record.sequence > previous.sequence)
          current.set(record.sourceId, record);
      }
    return [...current.values()];
  };
  const counts = (rows: readonly AnalyticsRecord[]) =>
    Object.freeze(
      rows.reduce<Record<string, number>>(
        (output, row) => ({
          ...output,
          [row.status ?? "unknown"]: (output[row.status ?? "unknown"] ?? 0) + 1,
        }),
        {},
      ),
    );
  const attempts = latest("timeline_events", "containment.attempt");
  const byAttempt = new Map<string, AnalyticsRecord[]>();
  for (const record of records)
    if (
      record.source === "timeline_events" &&
      record.category === "containment.attempt"
    )
      byAttempt.set(record.sourceId, [
        ...(byAttempt.get(record.sourceId) ?? []),
        record,
      ]);
  const durations = [...byAttempt.values()]
    .map((events) =>
      events.sort((left, right) => left.sequence - right.sequence),
    )
    .map(
      (events) =>
        Date.parse(events.at(-1)!.occurredAt) -
        Date.parse(events[0]!.occurredAt),
    )
    .filter((duration) => Number.isFinite(duration));
  const attemptToVerification = distribution(durations);
  return Object.freeze({
    provider: Object.freeze({
      status: counts(latest("provider_deliveries")),
      operation: countsBy(latest("provider_deliveries"), (row) => row.category),
      retries: latest("provider_deliveries").reduce(
        (total, row) =>
          total +
          Math.max(
            0,
            Number(row.sourceVersion.split(":")[0]?.split("@")[0]) - 1 || 0,
          ),
        0,
      ),
    }),
    guardrail: Object.freeze({
      status: counts(latest("timeline_events", "guardrail.plan_attempt")),
      reason: countsBy(
        latest("timeline_events", "guardrail.plan_attempt"),
        (row) =>
          row.status?.startsWith("blocked:")
            ? row.status.slice("blocked:".length)
            : "allowed",
      ),
    }),
    containment: Object.freeze({
      attempted: attempts.length,
      executed: attempts.filter((item) => item.status?.startsWith("completed:"))
        .length,
      verified: attempts.filter((item) => item.status === "completed:verified")
        .length,
      terminal: attempts.filter((item) => item.status !== "executing:not_run")
        .length,
      attemptToVerification,
    }),
    escalation: Object.freeze({
      expected,
      observed,
      matched: expected === observed,
    }),
    audit: Object.freeze({
      requiredBoundaries: records.filter(
        (record) => record.category === "trace.boundary",
      ).length,
      completeManifests: records.filter(
        (record) =>
          record.category === "trace.boundary" && record.status === "present",
      ).length,
    }),
  });
}

function countsBy(
  rows: readonly AnalyticsRecord[],
  value: (row: AnalyticsRecord) => string,
) {
  return Object.freeze(
    rows.reduce<Record<string, number>>(
      (output, row) => ({
        ...output,
        [value(row)]: (output[value(row)] ?? 0) + 1,
      }),
      {},
    ),
  );
}

function distribution(values: readonly number[]): AnalyticsMetricResult {
  if (!values.length) return { sampleCount: 0, value: null, reason: "NO_DATA" };
  const sorted = [...values].sort((left, right) => left - right);
  const percentile = (fraction: number) => {
    const index = (sorted.length - 1) * fraction;
    const floor = Math.floor(index);
    const ceil = Math.ceil(index);
    return sorted[floor]! + (sorted[ceil]! - sorted[floor]!) * (index - floor);
  };
  return {
    sampleCount: sorted.length,
    value: sorted.reduce((sum, value) => sum + value, 0) / sorted.length,
    distribution: {
      p50: percentile(0.5),
      p95: percentile(0.95),
      max: sorted.at(-1)!,
    },
  };
}

async function assertProductTrace(
  run: Awaited<ReturnType<typeof runMockDemo>>,
  scenario: "privilege" | "country" | "device",
  disposition: "approved" | "rejected" | "expired",
): Promise<{
  tenantId: string;
  incidentId: string;
  traceId: string;
  boundaries: readonly SanitizedTraceBoundary[];
  /** Raw public-API result, retained only until the terminal redaction scan. */
  redactionTrace: unknown;
}> {
  const operational = new LibSQLStore({
    id: `phase10-report-op-${scenario}`,
    url: pathToFileURL(run.journal.databasePath).href,
  });
  const trace = new LibSQLStore({
    id: `phase10-report-trace-${scenario}`,
    url: pathToFileURL(run.journal.traceDatabasePath).href,
  });
  const composite = new MastraCompositeStore({
    id: `phase10-report-composite-${scenario}`,
    default: operational,
    domains: { observability: trace.stores.observability },
  });
  await operational.init();
  await trace.init();
  await composite.init();
  const observability = createPhase4Observability();
  const reader = new Mastra({ storage: composite, observability });
  try {
    const raw = createLibSqlOperationalStore({
      url: `file:${run.journal.databasePath}`,
    });
    try {
      const row = await raw.execute({
        sql: "SELECT phase10_trace_json FROM workflow_runs WHERE run_id=?",
        args: [run.journal.workflowRunId ?? ""],
      });
      const carrier = JSON.parse(
        String(row.rows[0]?.phase10_trace_json ?? ""),
      ) as {
        traceId: string;
        scope: {
          tenantId: string;
          incidentId: string;
          runId: string;
          correlationId: string;
        };
      };
      const recorded = await observability.getRecordedTrace({
        traceId: phase10RecordedTraceId({
          traceId: carrier.traceId,
          ...carrier.scope,
        }),
      });
      if (!recorded)
        fail(
          exitCodes.trace,
          `PHASE10_E2E_TRACE_${scenario.toUpperCase()}_MISSING`,
        );
      const boundaries: SanitizedTraceBoundary[] = recorded.spans.map(
        (span) => ({
          spanId: span.id,
          traceId: span.traceId,
          name: String(
            (span.attributes as Record<string, unknown> | undefined)?.boundary,
          ),
          ...(span.parentSpanId ? { parentSpanId: span.parentSpanId } : {}),
          startMs: span.startTime.getTime(),
          ...(span.endTime ? { endMs: span.endTime.getTime() } : {}),
          attributes: (span.attributes ?? {}) as Record<string, unknown>,
        }),
      );
      const surface = JSON.stringify(
        recorded.spans.map((span) => ({
          attributes: span.attributes,
          input: span.input,
          output: span.output,
        })),
      );
      const traceErrors = validateTraceManifest(
        boundaries,
        phase10TraceManifest(scenario, disposition),
        [surface],
        ["phase10-secret-canary", "canary-sensitive", "198.51.100.8"],
      );
      if (traceErrors.length)
        fail(
          exitCodes.trace,
          `PHASE10_E2E_TRACE_${scenario.toUpperCase()}_INVALID:${traceErrors.join("|")}`,
        );
      return {
        tenantId: carrier.scope.tenantId,
        incidentId: carrier.scope.incidentId,
        traceId: carrier.traceId,
        boundaries,
        redactionTrace: recorded.spans.map((span) => ({
          id: span.id,
          traceId: span.traceId,
          parentSpanId: span.parentSpanId,
          attributes: span.attributes,
          input: span.input,
          output: span.output,
        })),
      };
    } finally {
      raw.close();
    }
  } finally {
    await observability.shutdown();
    await trace.close();
    await operational.close();
    void reader;
  }
}

async function exerciseOfflineReadModel(
  datasetVersion: string,
  recordedAt: string,
  inputs: Awaited<ReturnType<typeof loadPhase10Dataset>>["inputs"],
  expected: Awaited<ReturnType<typeof loadPhase10Dataset>>["expected"],
  observed: readonly Phase10Observed[],
): Promise<
  Readonly<{
    exported: number;
    sampleCount: number;
    scores: Readonly<
      Record<
        string,
        Readonly<{
          passed: boolean;
          numerator: number;
          denominator: number;
          details?: readonly string[];
          population?: "test-only";
        }>
      >
    >;
    caseResults: readonly Readonly<{
      caseId: string;
      status: "executed";
      skipped: false;
      errors: readonly string[];
      scoreFacts: Readonly<Record<string, unknown>>;
      legacyScoreFacts?: Readonly<{
        disposition: string;
        claims: readonly Readonly<{
          id: string;
          factual: boolean;
          evidenceRefs: readonly string[];
          evidenceHash: string;
        }>[];
        runbook: Readonly<{
          id: string;
          version: string;
          hash: string;
          satisfiedRules: readonly string[];
        }>;
        attempts: readonly Readonly<{
          action: string;
          executed: boolean;
          effect: Readonly<{ verified: boolean }> | null;
        }>[];
      }>;
      scorers: readonly Readonly<{
        evalId: string;
        passed: boolean;
        numerator: number;
        denominator: number;
        details?: readonly string[];
      }>[];
    }>[];
  }> &
    Readonly<{ redactionSinks: readonly RedactionSurface[] }>
> {
  const root = await mkdtemp(join(tmpdir(), "phase10-offline-"));
  const databasePath = join(root, "operational.db");
  const analyticsPath = join(root, "analytics.duckdb");
  const store = createLibSqlOperationalStore({ url: `file:${databasePath}` });
  const officialStorage = new LibSQLStore({
    id: "phase10-offline-scores",
    url: `file:${databasePath}`,
  });
  const analytics = new DuckDbAnalyticsStore(analyticsPath);
  try {
    await migrateOperationalStore(store, { appliedAt: recordedAt });
    await officialStorage.init();
    await seedPhase10AuthorityFromInputs(store, inputs, recordedAt);
    const scoreStore = await officialStorage.getStore("scores");
    if (!scoreStore)
      fail(exitCodes.infrastructure, "PHASE10_SCORES_STORE_MISSING");
    const perCaseAuthorities: Phase10Authority[] = [];
    const perCaseScoreDetails = new Map<
      string,
      Map<string, readonly string[]>
    >();
    for (const input of inputs) {
      const expectedCase = expected.find(
        (item) => item.caseId === input.caseId,
      )!;
      const observedCase = observed.find(
        (item) => item.caseId === input.caseId,
      )!;
      const authority = await readPhase10Authority(store, {
        tenantId: input.fixture.tenantAlias,
        incidentId: input.fixture.incidentAlias,
        workflowRunId: `offline-${input.caseId}`,
        asOf: recordedAt,
      });
      perCaseAuthorities.push(authority);
      const perCaseScores = await runPhase10MastraScorersDetailed({
        inputs: [input],
        expected: [expectedCase],
        observed: [observedCase],
        authority,
      });
      perCaseScoreDetails.set(
        input.caseId,
        new Map(
          perCaseScores.map((execution) => [
            execution.evalId,
            execution.score.details,
          ]),
        ),
      );
      for (const execution of perCaseScores) {
        const { evalId, officialScore, score } = execution;
        await persistSanitizedEvalResult(store, {
          id: `phase10-${input.caseId}-${evalId}`,
          datasetVersion,
          caseId: input.caseId,
          evalId,
          scorerVersion: "phase10-mastra-v1",
          tenantId: input.fixture.tenantAlias,
          incidentId: input.fixture.incidentAlias,
          workflowRunId: `offline-${input.caseId}`,
          passed: score.passed,
          numerator: score.numerator,
          denominator: score.denominator,
          recordedAt,
        });
        await scoreStore.saveScore({
          id: `phase10-score-${input.caseId}-${evalId}`,
          scorerId: evalId,
          score: score.passed ? 1 : 0,
          entityId: input.caseId,
          entityType: "WORKFLOW",
          runId: `offline-${input.caseId}`,
          input: { caseId: input.caseId },
          output: {
            passed: score.passed,
            numerator: score.numerator,
            denominator: score.denominator,
            officialScore,
          },
          source: "TEST",
          scorer: { id: evalId, version: "phase10-mastra-v1" },
          entity: { caseId: input.caseId },
          metadata: { datasetVersion, scorerVersion: "phase10-mastra-v1" },
        });
      }
      // This is a separate, append-only confusion observation: its labels
      // originate in the expected corpus and in the independently replayed
      // observed decision, rather than being inferred from a scenario label.
      const expectedLabel = expectedCase.disposition;
      const observedLabel = observedCase.decision.disposition;
      const expectedSeverity = expectedCase.severity;
      const observedSeverity = observedCase.decision.severity;
      const passed =
        expectedLabel === observedLabel &&
        expectedSeverity === observedSeverity;
      await persistSanitizedEvalResult(store, {
        id: `phase10-${input.caseId}-escalation-accuracy`,
        datasetVersion,
        caseId: input.caseId,
        evalId: "escalation_accuracy",
        scorerVersion: "phase10-confusion-v1",
        tenantId: input.fixture.tenantAlias,
        incidentId: input.fixture.incidentAlias,
        workflowRunId: `offline-${input.caseId}`,
        expectedDisposition: expectedLabel,
        observedDisposition: observedLabel,
        expectedSeverity,
        observedSeverity,
        passed,
        numerator: passed ? 1 : 0,
        denominator: 1,
        recordedAt,
      });
    }
    const aggregateAuthority: Phase10Authority = {
      evidence: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.evidence]),
      ),
      runbooks: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.runbooks]),
      ),
      approvals: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.approvals]),
      ),
      plans: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.plans]),
      ),
      actions: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.actions]),
      ),
      effects: new Map(
        perCaseAuthorities.flatMap((authority) => [...authority.effects]),
      ),
    };
    // Preserve the five official runs per case as the audit ledger, then run
    // the official severity scorer once on the frozen population. This is the
    // only invocation whose rational macro-F1 is the published severity gate.
    const aggregateOfficial = await runPhase10MastraScorersDetailed({
      inputs,
      expected,
      observed,
      authority: aggregateAuthority,
    });
    const severityAggregate = aggregateOfficial.find(
      (entry) => entry.evalId === "phase10Severity",
    );
    if (!severityAggregate)
      fail(exitCodes.infrastructure, "PHASE10_SEVERITY_AGGREGATE_MISSING");
    const persisted = await Promise.all(
      inputs.map((input) =>
        readSanitizedEvalResults(store, {
          datasetVersion,
          caseId: input.caseId,
        }),
      ),
    );
    if (persisted.length !== 72 || persisted.some((rows) => rows.length !== 6))
      fail(exitCodes.infrastructure, "PHASE10_SCORE_LEDGER_INVALID");
    const officialRows = await Promise.all(
      inputs.map((input) =>
        scoreStore.listScoresByRunId({
          runId: `offline-${input.caseId}`,
          pagination: { page: 0, perPage: 10 },
        }),
      ),
    );
    if (officialRows.some((page) => page.scores.length !== 5))
      fail(exitCodes.infrastructure, "PHASE10_OFFICIAL_SCORE_RELOAD_INVALID");
    for (const [index, page] of officialRows.entries()) {
      const rows = persisted[index]!;
      for (const resultRow of rows.filter(
        (row) => row.evalId !== "escalation_accuracy",
      )) {
        const official = page.scores.find(
          (item) =>
            item.scorerId === resultRow.evalId &&
            item.entityId === inputs[index]!.caseId &&
            item.runId === `offline-${inputs[index]!.caseId}`,
        );
        const output = official?.output as
          | {
              passed?: boolean;
              numerator?: number;
              denominator?: number;
              officialScore?: number;
            }
          | undefined;
        if (
          !official ||
          official.score !== (resultRow.passed ? 1 : 0) ||
          output?.passed !== resultRow.passed ||
          output.numerator !== resultRow.numerator ||
          output.denominator !== resultRow.denominator ||
          output.officialScore !== official.score
        )
          fail(
            exitCodes.infrastructure,
            "PHASE10_SCORE_RECONCILIATION_INVALID",
          );
      }
    }
    const scores = Object.fromEntries(
      [
        "phase10Severity",
        "phase10Attribution",
        "phase10Compliance",
        "phase10Hallucination",
        "phase10Safety",
      ].map((evalId) => {
        const rows = persisted.flat().filter((row) => row.evalId === evalId);
        const numerator = rows.reduce((total, row) => total + row.numerator, 0);
        if (evalId === "phase10Severity")
          return [
            evalId,
            {
              passed: severityAggregate.score.passed,
              numerator: severityAggregate.score.numerator,
              denominator: severityAggregate.score.denominator,
              details: severityAggregate.score.details,
              population: "test-only",
            },
          ];
        return [
          evalId,
          {
            passed: rows.every((row) => row.passed),
            numerator,
            denominator: rows.reduce(
              (total, row) => total + row.denominator,
              0,
            ),
          },
        ];
      }),
    );
    const confusionLedger = Object.freeze(
      persisted
        .flat()
        .filter((row) => row.evalId === "escalation_accuracy")
        .reduce<Record<string, number>>((output, row) => {
          const expectedLabel = `${row.expectedDisposition ?? "unknown"}/${row.expectedSeverity ?? "none"}`;
          const observedLabel = `${row.observedDisposition ?? "unknown"}/${row.observedSeverity ?? "none"}`;
          const key = `${expectedLabel}->${observedLabel}`;
          return { ...output, [key]: (output[key] ?? 0) + 1 };
        }, {}),
    );
    const exported = await exportAnalyticsSince(store, 0);
    await analytics.ingestBatch(exported);
    const incremental = await exportAnalyticsSince(
      store,
      exported.at(-1)?.sequence ?? 0,
    );
    if (incremental.length) await analytics.ingestBatch(incremental);
    const full = await exportAllAnalytics(store);
    await analytics.rebuild(full);
    const metrics = [];
    // DuckDB intentionally permits one writer/connection only.  Keep metric
    // reads serialized as well so a freshly rebuilt local store never races
    // its own lazy-open lock.
    for (const metric of analyticsMetricIds)
      metrics.push(
        await analytics.queryMetric({
          metric,
          tenantId: inputs[0]!.fixture.tenantAlias,
          from: recordedAt,
          to: "2026-08-31T00:00:00.000Z",
        }),
      );
    const evalRows = await store.execute({
      sql: "SELECT id,dataset_version,case_id,eval_id,scorer_version,tenant_id,incident_id,workflow_run_id,expected_disposition,observed_disposition,expected_severity,observed_severity,passed,numerator,denominator,result_hash,recorded_at FROM eval_results WHERE dataset_version=? ORDER BY case_id,eval_id",
      args: [datasetVersion],
    });
    const result = {
      exported: exported.length,
      sampleCount: metrics.reduce(
        (total, metric) => total + metric.sampleCount,
        0,
      ),
      scores,
      confusionLedger,
      caseResults: inputs.map((input, index) => ({
        caseId: input.caseId,
        status: "executed" as const,
        skipped: false as const,
        errors: [],
        scoreFacts: {
          decision: observed[index]!.decision,
          claims: observed[index]!.claims.map((claim) => ({
            ...claim,
            evidenceRefs: [...claim.evidenceRefs].sort(),
          })).sort((left, right) => left.id.localeCompare(right.id)),
          runbook: observed[index]!.runbook,
          attempts: observed[index]!.actionAttempts,
          authority: {
            evidenceRecords: [...perCaseAuthorities[index]!.evidence].sort(),
            runbooks: [...perCaseAuthorities[index]!.runbooks].sort(),
            approvals: [...perCaseAuthorities[index]!.approvals].sort(),
            plans: [...perCaseAuthorities[index]!.plans].sort(),
            actions: [...perCaseAuthorities[index]!.actions].sort(),
            effects: [...perCaseAuthorities[index]!.effects].sort(),
          },
        },
        // Escalation is intentionally a separate confusion ledger, never a
        // sixth scorer disguised as one of the 72×5 official rows.
        scorers: persisted[index]!.filter(
          (row) => row.evalId !== "escalation_accuracy",
        ).map((row) => ({
          ...row,
          details: perCaseScoreDetails.get(input.caseId)?.get(row.evalId) ?? [],
        })),
      })),
    };
    Object.defineProperty(result, "redactionSinks", {
      enumerable: false,
      value: Object.freeze([
        captureRedactionSurface(
          "duckdb-read-model:offline",
          await analytics.readFactRows(),
        ),
        captureRedactionSurface("libsql-eval-results", evalRows.rows),
        captureRedactionSurface(
          "official-score-ledger",
          officialRows.flatMap((page) => page.scores),
        ),
      ] satisfies readonly RedactionSurface[]),
    });
    return Object.freeze(result) as typeof result &
      Readonly<{ redactionSinks: readonly RedactionSurface[] }>;
  } finally {
    await analytics.close();
    store.close();
    await officialStorage.close();
    await rm(root, { recursive: true, force: true });
  }
}

function argumentValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}
function fail(code: number, message: string): never {
  const error = new Error(message) as Error & { exitCode?: number };
  error.exitCode = code;
  throw error;
}
// Keep a final promise boundary in addition to main's internal one. It makes
// future setup errors deterministic too instead of relying on Node's unhandled
// rejection behavior.
void main().catch(reportFailure);
