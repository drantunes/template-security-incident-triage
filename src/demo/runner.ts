import { createHmac, createHash, randomBytes } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

import { Mastra } from "@mastra/core/mastra";
import { EventEmitterPubSub } from "@mastra/core/events";
import { LibSQLStore } from "@mastra/libsql";
import { Hono } from "hono";

import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { migrateOperationalStore } from "../db/migrate.js";
import { createIncidentIngestionWorkflow } from "../mastra/workflows/incident-ingestion-workflow.js";
import { MockCloudEvidenceProvider } from "../providers/cloud-evidence-provider.js";
import { MockEndpointEvidenceProvider } from "../providers/endpoint-evidence-provider.js";
import { MockIdentityEvidenceProvider } from "../providers/identity-evidence-provider.js";
import { MockIncidentProvider } from "../providers/mock-incident-provider.js";
import { DeterministicRunbookEmbedder } from "../runbooks/embeddings.js";
import { indexRunbook } from "../runbooks/indexer.js";
import { loadRunbooks } from "../runbooks/loader.js";
import { retrieveRunbook } from "../runbooks/retrieve.js";
import { LibSqlRunbookVectorStore } from "../runbooks/vector-store.js";
import { deterministicResponsePlanner } from "../triage/prompt-safe-decision.js";
import { fixedClock } from "../domain/clock.js";
import type { MockContainmentState } from "../containment/mock-state.js";
import type { Phase2Config, Phase6Config } from "../env.js";
import { registerWebhookRoutes } from "../webhooks/routes.js";
import { registerApprovalRoutes } from "../approval/routes.js";
import { MockDecisionAuthenticator } from "../approval/mock-decision-authenticator.js";
import { createWorkflowApprovalRunReconciler } from "../approval/workflow-resume-reconciler.js";
import type { AppEnv } from "../http-context.js";
import { requestContextMiddleware } from "../http-context.js";
import { OutboxDispatcher } from "../background/outbox-dispatcher.js";
import { startWorkflowWorker } from "../background/workflow-worker.js";
import { Phase6RecoveryDispatcher } from "../background/phase6-recovery-dispatcher.js";
import {
  baselineIntegrityHash,
  type DemoEvidenceBaseline,
} from "./evidence-baseline.js";

import {
  DEMO_EXIT,
  exitForDemoError,
  type DemoJournal,
  type DemoRecord,
  type DemoScenario,
} from "./contracts.js";
import {
  DEMO_OCCURRED_AT,
  demoId,
  fixtureForScenario,
  scenarioDetailsFor,
} from "./fixtures.js";
import {
  demoRoot,
  newJournal,
  readJournal,
  removeOwnedDatabase,
  resourceHash,
  reserveOwnedDatabase,
  semanticDatabaseHash,
  writeJournal,
} from "./journal.js";
import { preflightDemo } from "./preflight.js";
import {
  calculatePlanHash,
  canonicalizePlanValue,
} from "../containment/plan-canonicalization.js";
import {
  Phase5ResultSchema,
  ValidatedContainmentPlanSchema,
} from "../triage/decision-contracts.js";
import { ExternalIncidentProjectionSchema } from "../providers/incident-provider.js";

const secret = "phase9-demo-webhook-secret-not-for-production";
const decisionSecret = "phase9-demo-decision-secret-not-for-production";
const resumeSecret = "phase9-demo-resume-secret-not-for-production";
// The webhook owns its received timestamp. Keep the deterministic workflow
// clock just ahead of that write so the operational monotonicity trigger is
// preserved even when this harness is run years after its fixture was added.
const fixedNow = new Date(Date.now() + 120_000).toISOString();

type RunOptions = Readonly<{
  scenario: DemoScenario;
  runKey: string;
  root?: string;
  decision?: "approve" | "reject" | "expire";
  timeoutMs?: number;
  signal?: AbortSignal;
}>;

export type DemoRunResult = Readonly<{
  exitCode: number;
  records: readonly DemoRecord[];
  journal: DemoJournal;
}>;

/**
 * The mock harness intentionally owns an isolated database per run. It sends
 * the fixture through the public signed webhook.  The persisted outbox is the
 * only path into the existing ingestion workflow: dispatcher -> mock PubSub ->
 * worker.  Keeping that boundary here prevents a demo from accidentally
 * becoming an internal-workflow smoke test.
 */
export async function runMockDemo(options: RunOptions): Promise<DemoRunResult> {
  const deadline =
    options.timeoutMs === undefined
      ? undefined
      : performance.now() + options.timeoutMs;
  const root = demoRoot(options.root);
  const runKeyHash = createHash("sha256").update(options.runKey).digest("hex");
  const demoRunId = demoId("demo", `${options.scenario}\0${runKeyHash}`);
  const existing = await readJournal(root, demoRunId);
  if (existing) {
    if (
      existing.scenario !== options.scenario ||
      existing.runKeyHash !== runKeyHash
    )
      throw new Error("DEMO_RUN_KEY_CONFLICT");
    if (options.decision && existing.state === "awaiting_approval")
      return decideMockDemo(
        root,
        existing,
        options.decision,
        options.timeoutMs,
        undefined,
        options.signal,
      );
    if (existing.state === "terminal") {
      const store = createLibSqlOperationalStore({
        url: pathToFileURL(existing.databasePath).href,
      });
      try {
        const approval = await store.execute({
          sql: "SELECT decision FROM approvals WHERE id = ? AND incident_id = ?",
          args: [existing.approvalId ?? "", existing.incidentId ?? ""],
        });
        const decision = approval.rows[0]?.decision;
        const verification =
          decision === "approved" || decision === "rejected"
            ? await verifyTerminal(
                store,
                existing,
                decision === "approved" ? "approve" : "reject",
                options.timeoutMs,
                options.signal,
              )
            : await verifyExpiredTerminal(store, existing);
        if (!verification.ok) throw new Error(verification.code);
      } finally {
        store.close();
      }
    }
    if (
      existing.state !== "awaiting_approval" &&
      existing.state !== "terminal" &&
      existing.state !== "cleaned"
    )
      throw new Error("DEMO_RECOVERY_REQUIRED_INSPECT_OR_CLEANUP");
    return {
      exitCode: existing.state === "cleaned" ? DEMO_EXIT.cleanup : DEMO_EXIT.ok,
      journal: existing,
      records: [
        record(existing, "state", {
          nextCommand: `npm run demo -- inspect --demo-run-id ${demoRunId}`,
        }),
      ],
    };
  }
  const preflight = preflightDemo({ mode: "mock" });
  if (!preflight.ok) throw new Error("DEMO_MOCK_PREFLIGHT_FAILED");
  await mkdir(root, { recursive: true, mode: 0o700 });
  let journal = await writeJournal(
    root,
    undefined,
    newJournal({ root, demoRunId, scenario: options.scenario, runKeyHash }),
  );
  const records: DemoRecord[] = [record(journal, "preflight")];
  const databaseUrl = pathToFileURL(journal.databasePath).href;
  let store: ReturnType<typeof createLibSqlOperationalStore> | undefined;
  let vector: LibSqlRunbookVectorStore | undefined;
  let runtime: Mastra | undefined;
  try {
    // Claim the exact database path before any schema or seed write.  An
    // interruption during migration can now be cleaned safely without
    // guessing whether the partial file belongs to this run.
    journal = await transition(root, journal, "seeding", [
      {
        kind: "local_database",
        ref: `local:${journal.demoRunId}`,
        ownership: "created",
        expectedHash: pendingDatabasePrecondition(journal.demoRunId),
      },
    ]);
    // The journal is durable before the filesystem effect.  A pre-existing
    // database or sidecar is rejected rather than adopted by this run.
    await reserveOwnedDatabase(root, journal);
    const reservedResources = await Promise.all(
      journal.resources.map(async (resource) =>
        resource.kind === "local_database"
          ? {
              ...resource,
              // A zero-byte file can only have come from the exclusive
              // reservation above. This journaled byte hash is the creation
              // proof used until a semantic DB snapshot is available.
              expectedHash: reservedDatabasePrecondition(
                await resourceHash(journal.databasePath),
              ),
            }
          : resource,
      ),
    );
    journal = await transition(
      root,
      journal,
      "seeding",
      reservedResources,
      {},
      { refreshDatabaseHash: false },
    );
    store = createLibSqlOperationalStore({ url: databaseUrl });
    throwIfAborted(options.signal);
    await migrateOperationalStore(store);
    throwIfDeadlineExceeded(deadline);
    throwIfAborted(options.signal);
    await seedScenarioBaseline(
      store,
      fixtureForScenario(options.scenario, demoRunId),
    );
    throwIfDeadlineExceeded(deadline);
    vector = new LibSqlRunbookVectorStore({ url: databaseUrl });
    for (const [index, runbook] of (
      await loadRunbooks(resolve(process.cwd(), "src/mastra/runbooks"))
    ).entries()) {
      await indexRunbook(
        store,
        vector,
        new DeterministicRunbookEmbedder(),
        runbook,
        {
          generationId: `${demoRunId}-rb-${index + 1}`,
          now: fixedNow,
        },
      );
    }
    journal = await transition(root, journal, "seeded", [
      {
        kind: "local_database",
        ref: `local:${demoRunId}`,
        ownership: "created",
        expectedHash: pendingDatabasePrecondition(journal.demoRunId),
      },
    ]);
    journal = await refreshDatabaseHash(root, journal);
    records.push(record(journal, "seed"));

    await vector.close();
    vector = undefined;
    const state = mockState(options.scenario, demoRunId);
    const workflow = createDemoWorkflow(databaseUrl, state);
    runtime = new Mastra({
      storage: new LibSQLStore({
        id: demoId("mastra", demoRunId),
        url: databaseUrl,
      }),
      workflows: { incidentIngestionWorkflow: workflow },
    });
    const app = new Hono<AppEnv>();
    registerWebhookRoutes(app, {
      config: phase2Config(),
      store,
      nowMs: () => Date.parse(fixedNow),
      logger: { write: () => {} },
    });
    const fixture = fixtureForScenario(options.scenario, demoRunId);
    const bytes = new TextEncoder().encode(JSON.stringify(fixture));
    const timestamp = String(Date.parse(fixedNow));
    const signature = createHmac("sha256", secret)
      .update(`${timestamp}.`)
      .update(bytes)
      .digest("hex");
    const response = await app.fetch(
      new Request("http://demo.local/webhooks/alerts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Alert-Signature": `t=${timestamp},v1=${signature}`,
        },
        body: bytes,
      }),
    );
    if (response.status !== 202) throw new Error("DEMO_WEBHOOK_REJECTED");
    const webhook = (await response.json()) as { incidentId?: string };
    if (!webhook.incidentId) throw new Error("DEMO_INCIDENT_MISSING");
    await persistScenarioEvidenceBaseline(store, fixture, webhook.incidentId);
    store.close();
    // libSQL releases a closed connection on the next turn; without this
    // boundary its writer can overlap the workflow's first durable marker.
    await new Promise<void>((done) => setImmediate(done));
    const pubsub = new EventEmitterPubSub();
    const workerStore = createLibSqlOperationalStore({ url: databaseUrl });
    const unsubscribe = await startWorkflowWorker({
      pubsub,
      workflow: runtime.getWorkflow("incidentIngestionWorkflow"),
      store: workerStore,
      logger: { write: () => {} },
      maxAttempts: 3,
    });
    const dispatcher = new OutboxDispatcher(
      workerStore,
      pubsub,
      phase2Config().outbox,
      { write: () => {} },
      () => new Date(fixedNow),
    );
    try {
      const published = await dispatcher.runOnce();
      if (published !== 1) throw new Error("DEMO_OUTBOX_NOT_PUBLISHED");
      // EventEmitterPubSub schedules subscribers asynchronously.  Do not tear
      // down its store after publish: wait for the worker's durable approval
      // marker, which also proves the async boundary was actually traversed.
      await waitForApproval(
        workerStore,
        webhook.incidentId,
        options.timeoutMs,
        options.signal,
      );
    } finally {
      await unsubscribe();
      await pubsub.close();
      workerStore.close();
    }
    const approvalStore = createLibSqlOperationalStore({ url: databaseUrl });
    const approval = await waitForApproval(
      approvalStore,
      webhook.incidentId,
      options.timeoutMs,
      options.signal,
    );
    const row = approval;
    if (
      !row ||
      typeof row.id !== "string" ||
      typeof row.plan_id !== "string" ||
      typeof row.workflow_run_id !== "string"
    ) {
      approvalStore.close();
      throw new Error("DEMO_APPROVAL_MISSING");
    }
    const workflowRunId = row.workflow_run_id;
    const outbox = await approvalStore.execute({
      sql: "SELECT published_at, attempt_count FROM outbox_events WHERE incident_id = ? AND type = 'security.alert.received'",
      args: [webhook.incidentId],
    });
    if (outbox.rows.length !== 1 || !outbox.rows[0]?.published_at) {
      approvalStore.close();
      throw new Error("DEMO_OUTBOX_NOT_CONVERGED");
    }
    journal = await transition(
      root,
      journal,
      "awaiting_approval",
      journal.resources,
      {
        incidentId: webhook.incidentId,
        workflowRunId,
        approvalId: row.id,
        planId: row.plan_id,
      },
    );
    records.push(
      record(journal, "trigger"),
      record(journal, "state"),
      record(journal, "approval_required"),
    );
    if (!options.decision) {
      approvalStore.close();
      journal = await refreshDatabaseHash(root, journal);
      return { exitCode: DEMO_EXIT.ok, records, journal };
    }
    approvalStore.close();
    return decideMockDemo(
      root,
      journal,
      options.decision,
      options.timeoutMs,
      records,
      options.signal,
    );
  } catch (error) {
    const code = error instanceof Error ? error.message : "DEMO_FAILED";
    const timedOut = code.includes("TIMEOUT");
    const interrupted = code === "DEMO_INTERRUPTED";
    // Any worker/dispatcher scope above has completed before this catch. Close
    // our remaining setup handles before taking the owned partial snapshot so
    // a normal WAL checkpoint cannot invalidate our own cleanup precondition.
    try {
      store?.close();
    } catch {
      /* closed by the webhook path */
    }
    // Once the exclusive reservation succeeded, snapshot the exact owned DB
    // before recording a partial state.  If reservation itself failed `store`
    // is absent and the pending claim remains intentionally uncleanable.
    if (store) {
      try {
        journal = await refreshDatabaseHash(root, journal);
      } catch {
        // Preserve the reserved byte-hash when no readable SQLite snapshot is
        // available; cleanup will then fail closed rather than guess.
      }
    }
    await vector?.close();
    vector = undefined;
    if (runtime) await shutdownDemoMastra(runtime);
    journal = await transition(
      root,
      journal,
      interrupted ? "interrupted" : timedOut ? "timed_out" : "failed",
    );
    records.push(
      record(journal, "error", {
        code,
      }),
    );
    return {
      exitCode: exitForDemoError(code),
      records,
      journal,
    };
  } finally {
    try {
      store?.close();
    } catch {
      /* the webhook store may already be closed */
    }
    await vector?.close();
    if (runtime) await shutdownDemoMastra(runtime);
  }
}

export async function inspectDemo(
  root: string | undefined,
  demoRunId: string,
): Promise<DemoJournal | undefined> {
  return readJournal(demoRoot(root), demoRunId);
}

export async function cleanupDemo(
  root: string | undefined,
  demoRunId: string,
): Promise<DemoJournal> {
  const journal = await readJournal(demoRoot(root), demoRunId);
  if (!journal) throw new Error("DEMO_RUN_NOT_FOUND");
  if (journal.state === "cleaned") return journal;
  const demoDirectory = demoRoot(root);
  // A concurrent cleaner owns the only transition from the frozen
  // precondition to deletion. Waiting for its terminal journal state keeps a
  // retry idempotent instead of returning a spurious journal CAS failure.
  if (journal.state === "cleaning")
    return await awaitConcurrentCleanup(demoDirectory, demoRunId);
  // Freeze the last authoritative observation before recording `cleaning`.
  // transition() must not refresh it: doing so would bless a concurrent DB
  // write immediately before deletion.
  let cleaning: DemoJournal;
  try {
    cleaning = await transition(
      demoDirectory,
      journal,
      "cleaning",
      journal.resources,
      {},
      {
        refreshDatabaseHash: false,
      },
    );
  } catch (error) {
    if (error instanceof Error && error.message === "DEMO_JOURNAL_CAS_CONFLICT")
      return await awaitConcurrentCleanup(demoDirectory, demoRunId);
    throw error;
  }
  try {
    await removeOwnedDatabase(demoDirectory, cleaning, {
      verifyPrecondition: (resource, databasePath) =>
        verifyDatabasePrecondition(
          cleaning,
          resource.expectedHash,
          databasePath,
        ),
    });
    return transition(
      demoDirectory,
      cleaning,
      "cleaned",
      cleaning.resources,
      {},
      {
        refreshDatabaseHash: false,
      },
    );
  } catch (error) {
    try {
      await transition(
        demoDirectory,
        cleaning,
        "cleanup_blocked",
        cleaning.resources,
        {},
        {
          refreshDatabaseHash: false,
        },
      );
    } catch (transitionError) {
      if (
        !(transitionError instanceof Error) ||
        transitionError.message !== "DEMO_JOURNAL_CAS_CONFLICT"
      )
        throw transitionError;
      return await awaitConcurrentCleanup(demoDirectory, demoRunId);
    }
    throw error;
  }
}

async function awaitConcurrentCleanup(
  root: string,
  demoRunId: string,
): Promise<DemoJournal> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const current = await readJournal(root, demoRunId);
    if (!current) throw new Error("DEMO_RUN_NOT_FOUND");
    if (current.state === "cleaned") return current;
    if (current.state !== "cleaning") {
      if (current.state === "cleanup_blocked")
        throw new Error("DEMO_CLEANUP_PRECONDITION_FAILED");
      // A non-cleaning state is not a success proof. Re-enter through the
      // public lifecycle so that it obtains a fresh CAS/frozen precondition.
      return cleanupDemo(root, demoRunId);
    }
    await new Promise<void>((done) => setTimeout(done, 10));
  }
  throw new Error("DEMO_CLEANUP_IN_PROGRESS");
}

/** Resume a suspended mock run through the persisted approval authority. */
export async function decideMockDemo(
  root: string,
  initial: DemoJournal,
  decision: "approve" | "reject" | "expire",
  timeoutMs?: number,
  prefix: DemoRecord[] = [],
  signal?: AbortSignal,
): Promise<DemoRunResult> {
  if (
    initial.state !== "awaiting_approval" ||
    !initial.incidentId ||
    !initial.approvalId ||
    !initial.planId
  )
    throw new Error("DEMO_APPROVAL_NOT_AWAITING_DECISION");
  if (decision === "expire")
    return expireMockDemo(root, initial, prefix, signal);
  const databaseUrl = pathToFileURL(initial.databasePath).href;
  const fixture = fixtureForScenario(initial.scenario, initial.demoRunId);
  const workflow = createDemoWorkflow(
    databaseUrl,
    mockState(initial.scenario, initial.demoRunId),
  );
  const mastra = new Mastra({
    storage: new LibSQLStore({
      id: demoId("mastra", initial.demoRunId),
      url: databaseUrl,
    }),
    workflows: { incidentIngestionWorkflow: workflow },
  });
  const store = createLibSqlOperationalStore({ url: databaseUrl });
  let journal = initial;
  const app = new Hono<AppEnv>();
  app.use(
    "*",
    requestContextMiddleware(() => demoId("request", initial.demoRunId)),
  );
  registerApprovalRoutes(app, {
    config: phase6Config(),
    store,
    logger: { write: () => {} },
    authenticator: new MockDecisionAuthenticator({
      mode: "mock",
      enabled: true,
      secret: decisionSecret,
      nowMs: () => Date.parse(fixedNow),
    }),
    reconcileApprovalRun: createWorkflowApprovalRunReconciler(
      mastra.getWorkflow("incidentIngestionWorkflow"),
    ),
    clock: fixedClock(fixedNow),
  });
  try {
    throwIfAborted(signal);
    if (
      !(await submitMockDecision(
        app,
        initial,
        fixture.tenantId,
        decision,
        signal,
      ))
    )
      throw new Error("DEMO_DECISION_REJECTED");
    throwIfAborted(signal);
    journal = await transition(root, journal, "decided");
    const verification = await verifyTerminal(
      store,
      journal,
      decision,
      timeoutMs,
      signal,
    );
    if (!verification.ok) throw new Error(verification.code);
    journal = await transition(root, journal, "terminal");
    journal = await refreshDatabaseHash(root, journal);
    const records = [
      ...prefix,
      record(journal, "terminal", {
        outcome: verification.outcome,
        runbookId: verification.runbookId,
        severity: verification.severity,
        actionTypes: verification.actionTypes,
      }),
      record(journal, "verification", {
        outcome: verification.outcome,
        runbookId: verification.runbookId,
        severity: verification.severity,
        actionTypes: verification.actionTypes,
        verificationRef: `local:${journal.demoRunId}:authoritative-projection`,
      }),
    ];
    return { exitCode: DEMO_EXIT.ok, records, journal };
  } catch (error) {
    const code = error instanceof Error ? error.message : "DEMO_FAILED";
    const interrupted = code === "DEMO_INTERRUPTED";
    const timedOut = code.includes("TIMEOUT");
    // Release the setup connection before snapshotting a partial database for
    // cleanup; otherwise a WAL writer can make our own precondition stale.
    try {
      store.close();
    } catch {
      /* closed by an earlier path */
    }
    journal = await transition(
      root,
      journal,
      interrupted ? "interrupted" : timedOut ? "timed_out" : "failed",
    );
    return {
      exitCode: exitForDemoError(code),
      journal,
      records: [
        ...prefix,
        record(journal, "error", {
          code,
        }),
      ],
    };
  } finally {
    store.close();
    await shutdownDemoMastra(mastra);
  }
}

/**
 * Drives the existing Phase 6 expiry dispatcher with a controlled local
 * clock. This is intentionally not an update of `expires_at`: the dispatcher
 * observes a genuinely due approval, commits the expiry event, and resumes
 * the suspended workflow through its bound `expiry_<approvalId>` receipt.
 */
async function expireMockDemo(
  root: string,
  initial: DemoJournal,
  prefix: DemoRecord[],
  signal?: AbortSignal,
): Promise<DemoRunResult> {
  if (!initial.incidentId || !initial.approvalId || !initial.workflowRunId)
    throw new Error("DEMO_IDS_MISSING");
  const databaseUrl = pathToFileURL(initial.databasePath).href;
  // The Phase 6 expiry path has no containment effect to reconcile. Keep its
  // provider response in-memory while the operational delivery ledger remains
  // authoritative; reopening a fresh DB-backed provider here would contend
  // with the still-active generation from the original open delivery.
  const expiryProvider = new MockIncidentProvider();
  const workflow = createDemoWorkflow(
    databaseUrl,
    mockState(initial.scenario, initial.demoRunId),
    expiryProvider,
  );
  const mastra = new Mastra({
    storage: new LibSQLStore({
      id: demoId("mastra", initial.demoRunId),
      url: databaseUrl,
    }),
    workflows: { incidentIngestionWorkflow: workflow },
  });
  const store = createLibSqlOperationalStore({ url: databaseUrl });
  let journal = initial;
  try {
    throwIfAborted(signal);
    const expiry = await store.execute({
      sql: "SELECT expires_at FROM approvals WHERE id = ? AND incident_id = ?",
      args: [initial.approvalId, initial.incidentId],
    });
    const expiresAt = expiry.rows[0]?.expires_at;
    if (typeof expiresAt !== "string") throw new Error("DEMO_APPROVAL_MISSING");
    const expiryMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiryMs)) throw new Error("DEMO_APPROVAL_INVALID");
    const clock = fixedClock(new Date(expiryMs + 1).toISOString());
    const dispatcher = new Phase6RecoveryDispatcher({
      store,
      provider: expiryProvider,
      clock,
      reconcileApprovalRun: createWorkflowApprovalRunReconciler(
        mastra.getWorkflow("incidentIngestionWorkflow"),
      ),
    });
    const result = await dispatcher.runOnce();
    if (result.expired !== 1) throw new Error("DEMO_EXPIRY_NOT_OBSERVED");
    throwIfAborted(signal);
    const verification = await verifyExpiredTerminal(store, journal);
    if (!verification.ok) throw new Error(verification.code);
    journal = await transition(root, journal, "terminal");
    journal = await refreshDatabaseHash(root, journal);
    return {
      exitCode: DEMO_EXIT.ok,
      journal,
      records: [
        ...prefix,
        record(journal, "terminal", { outcome: "expired" }),
        record(journal, "verification", {
          outcome: "expired",
          verificationRef: `local:${journal.demoRunId}:phase6-expiry`,
        }),
      ],
    };
  } catch (error) {
    const code = error instanceof Error ? error.message : "DEMO_FAILED";
    journal = await transition(root, journal, "failed");
    return {
      exitCode: exitForDemoError(code),
      journal,
      records: [...prefix, record(journal, "error", { code })],
    };
  } finally {
    store.close();
    await shutdownDemoMastra(mastra);
  }
}

async function shutdownDemoMastra(mastra: Mastra): Promise<void> {
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

async function waitForApproval(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  incidentId: string,
  timeoutMs = 60_000,
  signal?: AbortSignal,
): Promise<Record<string, unknown> | undefined> {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() <= deadline) {
    if (signal?.aborted) throw new Error("DEMO_INTERRUPTED");
    const result = await store.execute({
      sql: "SELECT id, plan_id, workflow_run_id FROM approvals WHERE incident_id = ?",
      args: [incidentId],
    });
    const row = result.rows[0];
    if (row) return row;
    await new Promise<void>((done) => setTimeout(done, 20));
  }
  throw new Error("DEMO_AWAITING_APPROVAL_TIMEOUT");
}

async function verifyExpiredTerminal(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  journal: DemoJournal,
): Promise<{ ok: true } | { ok: false; code: string }> {
  if (!journal.incidentId || !journal.workflowRunId || !journal.approvalId)
    return { ok: false, code: "DEMO_IDS_MISSING" };
  const state = await store.execute({
    sql: `SELECT i.status AS incident_status, i.severity AS incident_severity,
      w.status AS workflow_status, w.phase5_result_json,
      a.decision AS approval_decision, a.expiry_resumed_at,
      a.plan_hash AS approval_plan_hash,
      a.plan_hash_version AS approval_plan_hash_version,
      p.plan_hash, p.plan_hash_version, p.plan_json,
      (SELECT count(*) FROM containment_action_attempts ca
        WHERE ca.incident_id = i.id AND ca.plan_id = a.plan_id) AS attempts,
      (SELECT count(*) FROM mock_containment_effects effect
        WHERE effect.incident_id = i.id AND effect.plan_id = a.plan_id) AS effects,
      (SELECT count(*) FROM timeline_events timeline
        WHERE timeline.incident_id = i.id AND timeline.type = 'approval.expired') AS expiry_events
      FROM incidents i JOIN workflow_runs w
        ON w.incident_id = i.id AND w.run_id = ?
      JOIN approvals a ON a.incident_id = i.id AND a.id = ?
      JOIN containment_plans p ON p.incident_id = i.id AND p.id = a.plan_id
      WHERE i.id = ?`,
    args: [journal.workflowRunId, journal.approvalId, journal.incidentId],
  });
  const row = state.rows[0];
  let immutableMatches: boolean;
  try {
    const phase5 = Phase5ResultSchema.parse(
      JSON.parse(String(row?.phase5_result_json)),
    );
    const plan = ValidatedContainmentPlanSchema.parse(
      JSON.parse(String(row?.plan_json)),
    );
    immutableMatches =
      phase5.status === "ready-for-approval" &&
      phase5.decision.incidentId === journal.incidentId &&
      phase5.decision.workflowRunId === journal.workflowRunId &&
      row?.incident_severity === phase5.decision.severity &&
      plan.planId === journal.planId &&
      plan.incidentId === journal.incidentId &&
      plan.planHash === row?.plan_hash &&
      plan.planHashVersion === Number(row?.plan_hash_version) &&
      plan.planHash === row?.approval_plan_hash &&
      plan.planHashVersion === Number(row?.approval_plan_hash_version) &&
      calculatePlanHash(plan) === plan.planHash &&
      canonicalizePlanValue(plan) === canonicalizePlanValue(phase5.plan);
  } catch {
    immutableMatches = false;
  }
  return row &&
    row.incident_status === "failed" &&
    row.workflow_status === "completed" &&
    row.approval_decision === null &&
    typeof row.expiry_resumed_at === "string" &&
    Number(row.attempts) === 0 &&
    Number(row.effects) === 0 &&
    Number(row.expiry_events) === 1 &&
    immutableMatches
    ? { ok: true }
    : { ok: false, code: "DEMO_EXPIRY_PROJECTION_DIVERGED" };
}

/**
 * Validates the projection applicable to the journal lifecycle before an
 * external observer exposes a dashboard DTO or SSE replay. A suspended run is
 * a first-class observable state: it must prove the immutable Phase 5/plan
 * projection and the absence of containment, but must not be forced through a
 * terminal verifier prematurely.
 */
export async function verifyDemoSurfaceProjection(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  journal: DemoJournal,
): Promise<void> {
  if (!journal.incidentId || !journal.workflowRunId || !journal.approvalId)
    throw new Error("DEMO_IDS_MISSING");
  if (journal.state === "awaiting_approval") {
    const verification = await verifyAwaitingApprovalSurfaceProjection(
      store,
      journal,
    );
    if (!verification.ok) throw new Error(verification.code);
    return;
  }
  if (journal.state !== "terminal")
    throw new Error("DEMO_SURFACE_STATE_INVALID");
  const approval = await store.execute({
    sql: "SELECT decision FROM approvals WHERE id = ? AND incident_id = ?",
    args: [journal.approvalId, journal.incidentId],
  });
  const decision = approval.rows[0]?.decision;
  const verification =
    decision === "approved" || decision === "rejected"
      ? await verifyTerminal(
          store,
          journal,
          decision === "approved" ? "approve" : "reject",
          5_000,
        )
      : await verifyExpiredTerminal(store, journal);
  if (!verification.ok) throw new Error(verification.code);
}

async function verifyAwaitingApprovalSurfaceProjection(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  journal: DemoJournal,
): Promise<{ ok: true } | { ok: false; code: string }> {
  if (
    !journal.incidentId ||
    !journal.workflowRunId ||
    !journal.approvalId ||
    !journal.planId
  )
    return { ok: false, code: "DEMO_IDS_MISSING" };
  const result = await store.execute({
    sql: `SELECT i.status AS incident_status, i.kind AS incident_kind,
      i.severity AS incident_severity, i.tenant_id,
      w.status AS workflow_status, w.incident_id AS workflow_incident_id,
      w.phase5_result_json,
      a.decision AS approval_decision, a.expiry_resumed_at,
      a.incident_id AS approval_incident_id, a.plan_id AS approval_plan_id,
      a.plan_hash AS approval_plan_hash,
      a.plan_hash_version AS approval_plan_hash_version,
      p.plan_hash, p.plan_hash_version, p.plan_json,
      (SELECT count(*) FROM containment_actions action
        WHERE action.incident_id = i.id AND action.plan_id = p.id) AS action_count,
      (SELECT count(*) FROM containment_actions action
        WHERE action.incident_id = i.id AND action.plan_id = p.id
          AND action.status = 'pending' AND action.result_ref IS NULL) AS pending_action_count,
      (SELECT count(*) FROM containment_action_attempts attempt
        WHERE attempt.incident_id = i.id AND attempt.plan_id = p.id) AS attempt_count,
      (SELECT count(*) FROM mock_containment_effects effect
        WHERE effect.incident_id = i.id AND effect.plan_id = p.id) AS effect_count,
      (SELECT count(*) FROM provider_deliveries delivery
        WHERE delivery.incident_id = i.id AND delivery.operation = 'open-awaiting-approval'
          AND delivery.status IN ('completed', 'delivered', 'succeeded')) AS open_delivery_count
      FROM incidents i
      JOIN workflow_runs w ON w.run_id = ? AND w.incident_id = i.id
      JOIN approvals a ON a.id = ? AND a.incident_id = i.id
      JOIN containment_plans p ON p.id = a.plan_id AND p.incident_id = i.id
      WHERE i.id = ?`,
    args: [journal.workflowRunId, journal.approvalId, journal.incidentId],
  });
  const row = result.rows[0];
  if (!row) return { ok: false, code: "DEMO_AUTHORITATIVE_ROWS_MISSING" };
  let immutableMatches: boolean;
  try {
    const phase5 = Phase5ResultSchema.parse(
      JSON.parse(String(row.phase5_result_json)),
    );
    const plan = ValidatedContainmentPlanSchema.parse(
      JSON.parse(String(row.plan_json)),
    );
    const expected = scenarioDetailsFor(journal.scenario);
    immutableMatches =
      phase5.status === "ready-for-approval" &&
      phase5.decision.incidentId === journal.incidentId &&
      phase5.decision.workflowRunId === journal.workflowRunId &&
      row.incident_kind ===
        fixtureForScenario(journal.scenario, journal.demoRunId).kind &&
      row.incident_severity === phase5.decision.severity &&
      plan.planId === journal.planId &&
      plan.incidentId === journal.incidentId &&
      plan.tenantId === row.tenant_id &&
      plan.planHash === row.plan_hash &&
      plan.planHashVersion === Number(row.plan_hash_version) &&
      plan.planHash === row.approval_plan_hash &&
      plan.planHashVersion === Number(row.approval_plan_hash_version) &&
      calculatePlanHash(plan) === plan.planHash &&
      canonicalizePlanValue(plan) === canonicalizePlanValue(phase5.plan) &&
      plan.actions.length === expected.actions.length &&
      plan.actions.every((action) =>
        (expected.actions as readonly string[]).includes(action.type),
      );
  } catch {
    immutableMatches = false;
  }
  return row.incident_status === "awaiting_approval" &&
    row.workflow_status === "running" &&
    row.workflow_incident_id === journal.incidentId &&
    row.approval_incident_id === journal.incidentId &&
    row.approval_plan_id === journal.planId &&
    row.approval_decision === null &&
    row.expiry_resumed_at === null &&
    Number(row.action_count) === Number(row.pending_action_count) &&
    Number(row.attempt_count) === 0 &&
    Number(row.effect_count) === 0 &&
    Number(row.open_delivery_count) === 1 &&
    immutableMatches
    ? { ok: true }
    : { ok: false, code: "DEMO_AWAITING_APPROVAL_PROJECTION_DIVERGED" };
}

async function verifyTerminal(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  journal: DemoJournal,
  decision: "approve" | "reject",
  timeoutMs = 120_000,
  signal?: AbortSignal,
): Promise<
  | {
      ok: true;
      outcome: "contained" | "rejected";
      runbookId: string;
      severity: "low" | "medium" | "high";
      actionTypes: readonly string[];
    }
  | { ok: false; code: string }
> {
  const expected = scenarioDetailsFor(journal.scenario);
  if (!journal.incidentId || !journal.workflowRunId || !journal.approvalId)
    return { ok: false, code: "DEMO_IDS_MISSING" };
  const deadline = performance.now() + timeoutMs;
  while (performance.now() <= deadline) {
    throwIfAborted(signal);
    const result = await store.execute({
      sql: `SELECT i.status AS incident_status, i.kind AS incident_kind,
        i.severity AS incident_severity,
        w.status AS workflow_status, w.incident_id AS workflow_incident_id,
        w.phase5_result_json AS phase5_result_json,
        a.decision AS approval_decision,
        a.incident_id AS approval_incident_id, a.plan_id AS approval_plan_id,
        a.plan_hash AS approval_plan_hash,
        a.plan_hash_version AS approval_plan_hash_version,
        p.plan_hash AS plan_hash, p.plan_hash_version AS plan_hash_version,
        p.plan_json AS plan_json, i.tenant_id AS tenant_id,
        (SELECT runbook_id FROM runbook_retrievals rr WHERE rr.incident_id = i.id
          AND rr.status = 'succeeded' ORDER BY rr.selected_at DESC LIMIT 1) AS runbook_id,
        (SELECT count(*) FROM timeline_events t WHERE t.incident_id = i.id) AS timeline_count,
        (SELECT count(*) FROM containment_actions c WHERE c.incident_id = i.id AND c.plan_id = a.plan_id) AS action_count,
        (SELECT count(*) FROM containment_actions c WHERE c.incident_id = i.id AND c.plan_id = a.plan_id AND c.status = 'completed') AS completed_action_count,
        (SELECT count(*) FROM containment_action_attempts ca WHERE ca.incident_id = i.id AND ca.plan_id = a.plan_id AND ca.status = 'completed' AND ca.verification = 'verified') AS attempt_count,
        (SELECT count(*) FROM provider_deliveries pd WHERE pd.incident_id = i.id AND pd.status IN ('completed','delivered','succeeded')) AS delivery_count
        FROM incidents i JOIN workflow_runs w ON w.run_id = ? AND w.incident_id = i.id
          JOIN approvals a ON a.id = ? AND a.incident_id = i.id AND a.plan_id = i.current_plan_id
          JOIN containment_plans p ON p.id = a.plan_id AND p.incident_id = i.id
        WHERE i.id = ?`,
      args: [journal.workflowRunId, journal.approvalId, journal.incidentId],
    });
    const row = result.rows[0];
    if (!row) return { ok: false, code: "DEMO_AUTHORITATIVE_ROWS_MISSING" };
    const rejected = decision === "reject";
    const terminal = rejected
      ? row.incident_status === "closed" && row.approval_decision === "rejected"
      : row.incident_status === "closed" &&
        row.approval_decision === "approved";
    let authoritative:
      | {
          severity: "low" | "medium" | "high";
          runbookId: string;
          plan: ReturnType<typeof ValidatedContainmentPlanSchema.parse>;
        }
      | undefined;
    try {
      const phase5 = Phase5ResultSchema.parse(
        JSON.parse(String(row.phase5_result_json)),
      );
      if (phase5.status !== "ready-for-approval")
        return { ok: false, code: "DEMO_PHASE5_RESULT_INVALID" };
      const severity = phase5.decision.severity;
      const runbookReference = phase5.decision.runbookReference;
      const runbook =
        typeof runbookReference === "string"
          ? /^\[runbook:([^@\]]+)@[0-9]+\.[0-9]+\.[0-9]+\]$/u.exec(
              runbookReference,
            )?.[1]
          : undefined;
      if (
        (severity === "low" || severity === "medium" || severity === "high") &&
        typeof runbook === "string" &&
        phase5.decision.incidentId === journal.incidentId &&
        phase5.decision.workflowRunId === journal.workflowRunId
      )
        authoritative = { severity, runbookId: runbook, plan: phase5.plan };
    } catch {
      return { ok: false, code: "DEMO_PHASE5_RESULT_INVALID" };
    }
    const projectionMatches =
      row.incident_kind ===
        fixtureForScenario(journal.scenario, journal.demoRunId).kind &&
      row.workflow_status === "completed" &&
      Number(row.timeline_count) > 0 &&
      Number(row.action_count) === expected.actions.length &&
      Number(row.delivery_count) > 0 &&
      row.incident_severity === authoritative?.severity &&
      row.runbook_id === authoritative?.runbookId &&
      typeof row.plan_hash === "string" &&
      typeof row.plan_json === "string";
    if (terminal && projectionMatches) {
      let approvedPlan: ReturnType<typeof ValidatedContainmentPlanSchema.parse>;
      try {
        approvedPlan = ValidatedContainmentPlanSchema.parse(
          JSON.parse(String(row.plan_json)),
        );
      } catch {
        return { ok: false, code: "DEMO_PLAN_INVALID" };
      }
      const actionTypes = approvedPlan.actions.map((action) => action.type);
      const planIsAuthoritative =
        approvedPlan.planId === journal.planId &&
        approvedPlan.incidentId === journal.incidentId &&
        approvedPlan.tenantId === row.tenant_id &&
        approvedPlan.planHash === row.plan_hash &&
        approvedPlan.planHashVersion === Number(row.plan_hash_version) &&
        approvedPlan.planHash === row.approval_plan_hash &&
        approvedPlan.planHashVersion ===
          Number(row.approval_plan_hash_version) &&
        calculatePlanHash(approvedPlan) === approvedPlan.planHash &&
        authoritative &&
        canonicalizePlanValue(approvedPlan) ===
          canonicalizePlanValue(authoritative.plan);
      if (!planIsAuthoritative)
        return { ok: false, code: "DEMO_PLAN_INTEGRITY_DIVERGED" };
      if (
        actionTypes.length !== expected.actions.length ||
        [...actionTypes].sort().join("\0") !==
          [...expected.actions].sort().join("\0")
      )
        return { ok: false, code: "DEMO_PLAN_ACTIONS_DIVERGED" };
      if (!authoritative)
        return { ok: false, code: "DEMO_PHASE5_PLAN_DIVERGED" };
      if (
        !(await verifyActionProjection(
          store,
          journal,
          approvedPlan,
          decision,
          String(row.tenant_id),
          authoritative.severity,
        ))
      )
        return { ok: false, code: "DEMO_ACTION_PROJECTION_DIVERGED" };
      if (rejected && Number(row.attempt_count) !== 0)
        return { ok: false, code: "DEMO_REJECT_CONTAINMENT_ATTEMPTED" };
      if (!rejected && Number(row.attempt_count) === 0)
        return { ok: false, code: "DEMO_APPROVE_CONTAINMENT_MISSING" };
      if (
        !rejected &&
        Number(row.completed_action_count) !== expected.actions.length
      )
        return { ok: false, code: "DEMO_ACTIONS_NOT_COMPLETED" };
      return {
        ok: true,
        outcome: rejected ? "rejected" : "contained",
        runbookId: authoritative.runbookId,
        severity: authoritative.severity,
        actionTypes,
      };
    }
    // Once both operational terminal markers have been written they are
    // immutable evidence, not an eventually-consistent intermediate.  A rerun
    // must fail immediately instead of waiting out its budget and reporting a
    // stale terminal journal as success.
    if (terminal && row.workflow_status === "completed")
      return { ok: false, code: "DEMO_TERMINAL_PROJECTION_DIVERGED" };
    await new Promise<void>((done) => setTimeout(done, 25));
  }
  return { ok: false, code: "DEMO_TERMINAL_VERIFICATION_TIMEOUT" };
}

/**
 * The plan is not the authoritative execution record.  Bind every persisted
 * action, attempt and mock effect back to the exact approved action before a
 * terminal rerun is allowed to report success.  Counts alone would allow a
 * schema-valid substitution to hide behind the same cardinality.
 */
async function verifyActionProjection(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  journal: DemoJournal,
  plan: { actions?: unknown },
  decision: "approve" | "reject",
  tenantId: string,
  severity: "low" | "medium" | "high",
): Promise<boolean> {
  if (
    !journal.incidentId ||
    !journal.planId ||
    !journal.approvalId ||
    !Array.isArray(plan.actions)
  )
    return false;
  const expected = plan.actions.map((value, ordinal) => {
    if (!value || typeof value !== "object") return undefined;
    const action = value as Record<string, unknown>;
    if (
      typeof action.actionId !== "string" ||
      typeof action.type !== "string" ||
      typeof action.targetId !== "string" ||
      !action.input ||
      typeof action.input !== "object"
    )
      return undefined;
    return {
      actionId: action.actionId,
      type: action.type,
      targetId: action.targetId,
      input: canonicalizePlanValue(action.input),
      ordinal,
    };
  });
  if (expected.some((action) => !action)) return false;
  const expectedActions = expected as Array<{
    actionId: string;
    type: string;
    targetId: string;
    input: string;
    ordinal: number;
  }>;
  const actions = await store.execute({
    sql: `SELECT action_id, action_type, target_id, ordinal, input_json,
      idempotency_key, status, result_ref
      FROM containment_actions
      WHERE incident_id = ? AND plan_id = ? ORDER BY ordinal`,
    args: [journal.incidentId, journal.planId],
  });
  if (actions.rows.length !== expectedActions.length) return false;
  if (
    new Set(actions.rows.map((row) => String(row.action_id))).size !==
    expectedActions.length
  )
    return false;
  const byAction = new Map(
    expectedActions.map((action) => [action.actionId, action]),
  );
  for (const row of actions.rows) {
    const action = byAction.get(String(row.action_id));
    if (
      !action ||
      row.action_type !== action.type ||
      row.target_id !== action.targetId ||
      Number(row.ordinal) !== action.ordinal ||
      row.idempotency_key !== `${journal.planId}:${action.actionId}`
    )
      return false;
    try {
      if (
        canonicalizePlanValue(JSON.parse(String(row.input_json))) !==
        action.input
      )
        return false;
    } catch {
      return false;
    }
    if (decision === "reject") {
      if (row.status !== "pending" || row.result_ref !== null) return false;
    } else if (
      row.status !== "completed" ||
      row.result_ref !== `mock-action-${action.actionId}`
    )
      return false;
  }
  const attempts = await store.execute({
    sql: `SELECT action_id, approval_id, idempotency_key, attempt, status,
      verification, provider_ref, fence_token
      FROM containment_action_attempts
      WHERE incident_id = ? AND plan_id = ? ORDER BY action_id, attempt`,
    args: [journal.incidentId, journal.planId],
  });
  const effects = await store.execute({
    sql: `SELECT action_id, action_type, target_id, input_json, attempt,
      fence_token, provider_ref
      FROM mock_containment_effects
      WHERE incident_id = ? AND plan_id = ? ORDER BY action_id`,
    args: [journal.incidentId, journal.planId],
  });
  if (decision === "reject") {
    if (attempts.rows.length !== 0 || effects.rows.length !== 0) return false;
  } else {
    if (
      attempts.rows.length !== expectedActions.length ||
      effects.rows.length !== expectedActions.length
    )
      return false;
    if (
      new Set(attempts.rows.map((row) => String(row.action_id))).size !==
        expectedActions.length ||
      new Set(effects.rows.map((row) => String(row.action_id))).size !==
        expectedActions.length
    )
      return false;
    const attemptByAction = new Map(
      attempts.rows.map((row) => [String(row.action_id), row]),
    );
    const effectByAction = new Map(
      effects.rows.map((row) => [String(row.action_id), row]),
    );
    for (const action of expectedActions) {
      const attempt = attemptByAction.get(action.actionId);
      const effect = effectByAction.get(action.actionId);
      if (
        !attempt ||
        !effect ||
        attempt.approval_id !== journal.approvalId ||
        attempt.idempotency_key !== `${journal.planId}:${action.actionId}` ||
        Number(attempt.attempt) !== 1 ||
        attempt.status !== "completed" ||
        attempt.verification !== "verified" ||
        attempt.provider_ref !== `mock-action-${action.actionId}` ||
        typeof attempt.fence_token !== "string" ||
        effect.action_type !== action.type ||
        effect.target_id !== action.targetId ||
        Number(effect.attempt) !== 1 ||
        effect.fence_token !== attempt.fence_token ||
        effect.provider_ref !== attempt.provider_ref
      )
        return false;
      try {
        if (
          canonicalizePlanValue(JSON.parse(String(effect.input_json))) !==
          action.input
        )
          return false;
      } catch {
        return false;
      }
    }
  }
  const deliveries = await store.execute({
    sql: `SELECT provider, operation, tenant_id, idempotency_key, status,
      attempt_count, workflow_run_id, correlation_id, projection_json,
      external_ref, error_code, provider_generation
      FROM provider_deliveries WHERE incident_id = ?`,
    args: [journal.incidentId],
  });
  const providerEffects = await store.execute({
    sql: `SELECT operation, tenant_id, idempotency_key, generation,
      projection_json, external_ref
      FROM mock_incident_provider_effects WHERE incident_id = ?`,
    args: [journal.incidentId],
  });
  const expectedDeliveries = [
    {
      deliveryOperation: "open-awaiting-approval",
      effectOperation: "create",
      status: "awaiting_approval",
      summaryCode: scenarioSummaryCode(journal.scenario),
    },
    {
      deliveryOperation:
        decision === "reject" ? "decision-rejected" : "final-contained",
      effectOperation: "update",
      status: decision === "reject" ? "rejected" : "contained",
      summaryCode:
        decision === "reject"
          ? "CONTAINMENT_REJECTED"
          : "CONTAINMENT_SUCCEEDED",
    },
  ] as const;
  if (
    deliveries.rows.length !== expectedDeliveries.length ||
    providerEffects.rows.length !== expectedDeliveries.length ||
    new Set(deliveries.rows.map((row) => String(row.operation))).size !==
      expectedDeliveries.length ||
    new Set(providerEffects.rows.map((row) => String(row.idempotency_key)))
      .size !== expectedDeliveries.length
  )
    return false;
  const deliveryByOperation = new Map(
    deliveries.rows.map((row) => [String(row.operation), row]),
  );
  const effectByIdempotencyKey = new Map(
    providerEffects.rows.map((row) => [String(row.idempotency_key), row]),
  );
  const correlations = new Set<string>();
  for (const expectedDelivery of expectedDeliveries) {
    const delivery = deliveryByOperation.get(
      expectedDelivery.deliveryOperation,
    );
    const idempotencyKey = `mock-incident:${journal.incidentId}:${expectedDelivery.deliveryOperation}`;
    const effect = effectByIdempotencyKey.get(idempotencyKey);
    if (
      !delivery ||
      !effect ||
      delivery.provider !== "mock-incident" ||
      delivery.tenant_id !== tenantId ||
      delivery.idempotency_key !== idempotencyKey ||
      delivery.status !== "succeeded" ||
      Number(delivery.attempt_count) !== 1 ||
      delivery.workflow_run_id !== journal.workflowRunId ||
      typeof delivery.correlation_id !== "string" ||
      !delivery.correlation_id ||
      delivery.error_code !== null ||
      effect.operation !== expectedDelivery.effectOperation ||
      effect.tenant_id !== tenantId ||
      Number(effect.generation) !== Number(delivery.provider_generation) ||
      effect.external_ref !== delivery.external_ref ||
      effect.projection_json !== delivery.projection_json
    )
      return false;
    correlations.add(delivery.correlation_id);
    try {
      const projection = ExternalIncidentProjectionSchema.parse(
        JSON.parse(String(delivery.projection_json)),
      );
      if (
        projection.incidentId !== journal.incidentId ||
        projection.tenantId !== tenantId ||
        projection.kind !==
          fixtureForScenario(journal.scenario, journal.demoRunId).kind ||
        projection.severity !== severity ||
        projection.status !== expectedDelivery.status ||
        projection.summaryCode !== expectedDelivery.summaryCode ||
        projection.planHash !== (plan as { planHash?: unknown }).planHash ||
        projection.planHashVersion !==
          (plan as { planHashVersion?: unknown }).planHashVersion ||
        canonicalizePlanValue(projection.actionTypes) !==
          canonicalizePlanValue(expectedActions.map((action) => action.type))
      )
        return false;
    } catch {
      return false;
    }
  }
  return correlations.size === 1;
}

function scenarioSummaryCode(scenario: DemoScenario): string {
  return {
    privilege: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
    country: "COUNTRY_LOGIN_REQUIRES_REVIEW",
    device: "UNKNOWN_DEVICE_REQUIRES_REVIEW",
  }[scenario];
}

async function refreshDatabaseHash(
  root: string,
  journal: DemoJournal,
): Promise<DemoJournal> {
  const resources = await Promise.all(
    journal.resources.map(async (resource) =>
      resource.kind === "local_database"
        ? {
            ...resource,
            expectedHash: await semanticDatabaseHash(journal.databasePath),
          }
        : resource,
    ),
  );
  return transition(root, journal, journal.state, resources);
}

function pendingDatabasePrecondition(demoRunId: string): string {
  return `pending:${demoRunId}`;
}

function reservedDatabasePrecondition(hash: string): string {
  return `reserved:${hash}`;
}

async function verifyDatabasePrecondition(
  journal: DemoJournal,
  expectedHash: string,
  databasePath: string,
): Promise<boolean> {
  // A pending claim is deliberately *not* ownership proof: a crash before the
  // exclusive reservation must never make cleanup adopt a foreign DB.  The
  // reserved marker is a hash of the zero-byte file created with `wx`.
  if (expectedHash === pendingDatabasePrecondition(journal.demoRunId))
    return false;
  if (expectedHash.startsWith("reserved:"))
    return (
      (await resourceHash(databasePath)) ===
      expectedHash.slice("reserved:".length)
    );
  return (await semanticDatabaseHash(databasePath)) === expectedHash;
}

/**
 * Hash logical table content rather than the SQLite main-db file.  SQLite may
 * legitimately checkpoint WAL pages while a user merely inspects the demo;
 * that changes bytes without changing the owned resource's meaning.  The
 * canonical row ordering still detects a real concurrent mutation.
 */
function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error("DEMO_INTERRUPTED");
}

function throwIfDeadlineExceeded(deadline: number | undefined): void {
  if (deadline !== undefined && performance.now() > deadline)
    throw new Error("DEMO_AWAITING_APPROVAL_TIMEOUT");
}

async function transition(
  root: string,
  journal: DemoJournal,
  state: DemoJournal["state"],
  resources = journal.resources,
  fields: Partial<
    Pick<DemoJournal, "incidentId" | "workflowRunId" | "approvalId" | "planId">
  > = {},
  options: Readonly<{ refreshDatabaseHash?: boolean }> = {},
): Promise<DemoJournal> {
  const synchronizedResources = await Promise.all(
    resources.map(async (resource) => {
      if (resource.kind !== "local_database") return resource;
      if (
        resource.expectedHash.startsWith("pending:") ||
        resource.expectedHash.startsWith("reserved:") ||
        options.refreshDatabaseHash === false
      )
        return resource;
      return {
        ...resource,
        expectedHash: await semanticDatabaseHash(journal.databasePath),
      };
    }),
  );
  return writeJournal(root, journal, {
    schemaVersion: 1,
    demoRunId: journal.demoRunId,
    scenario: journal.scenario,
    mode: "mock",
    runKeyHash: journal.runKeyHash,
    state,
    createdAt: journal.createdAt,
    databasePath: journal.databasePath,
    resources: synchronizedResources,
    ...(journal.incidentId ? { incidentId: journal.incidentId } : {}),
    ...(journal.workflowRunId ? { workflowRunId: journal.workflowRunId } : {}),
    ...(journal.approvalId ? { approvalId: journal.approvalId } : {}),
    ...(journal.planId ? { planId: journal.planId } : {}),
    ...fields,
  });
}

function record(
  journal: DemoJournal,
  type: DemoRecord["type"],
  extra: Partial<DemoRecord> = {},
): DemoRecord {
  return {
    schemaVersion: 1,
    type,
    demoRunId: journal.demoRunId,
    scenario: journal.scenario,
    mode: journal.mode,
    state: journal.state,
    occurredAt: journal.updatedAt,
    ...(journal.incidentId ? { incidentId: journal.incidentId } : {}),
    ...(journal.workflowRunId ? { workflowRunId: journal.workflowRunId } : {}),
    ...(journal.approvalId ? { approvalId: journal.approvalId } : {}),
    ...(journal.planId ? { planId: journal.planId } : {}),
    ...extra,
  };
}

function phase2Config(): Phase2Config {
  return {
    mode: "mock",
    webhooksEnabled: true,
    alertWebhookSecret: secret,
    workosWebhookSecret: secret,
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

function phase6Config(): Phase6Config {
  return {
    mode: "mock",
    mockDecisionsEnabled: true,
    mockDecisionSecret: decisionSecret,
    approvalResumeSecret: resumeSecret,
    actionTimeoutMs: 1_000,
    rateLimit: 8,
  };
}

function mockState(
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

function createDemoWorkflow(
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

async function submitMockDecision(
  app: Hono<AppEnv>,
  journal: DemoJournal,
  tenantId: string,
  decision: "approve" | "reject",
  signal?: AbortSignal,
): Promise<boolean> {
  throwIfAborted(signal);
  if (!journal.incidentId || !journal.approvalId || !journal.planId)
    return false;
  const body = JSON.stringify({
    planId: journal.planId,
    planHashVersion: 1,
    planHash: await readPlanHash(journal),
    decision: decision === "approve" ? "approved" : "rejected",
    ...(decision === "reject" ? { reason: "Demo rejection." } : {}),
  });
  const nonce = randomBytes(16).toString("base64url");
  const path = `/api/incidents/${journal.incidentId}/approvals/${journal.approvalId}/decision`;
  const timestamp = Date.parse(fixedNow);
  const signature = createHmac("sha256", decisionSecret)
    .update(`${timestamp}.${nonce}.POST.${path}.${tenantId}.`)
    .update(body)
    .digest("hex");
  const response = await app.fetch(
    new Request(`http://demo.local${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Decision-Tenant": tenantId,
        "X-Decision-Nonce": nonce,
        "X-Decision-Signature": `t=${timestamp},v1=${signature}`,
      },
      body,
    }),
  );
  throwIfAborted(signal);
  return response.status === 200;
}

async function readPlanHash(journal: DemoJournal): Promise<string> {
  if (!journal.databasePath || !journal.approvalId)
    throw new Error("DEMO_APPROVAL_MISSING");
  const store = createLibSqlOperationalStore({
    url: pathToFileURL(journal.databasePath).href,
  });
  try {
    const result = await store.execute({
      sql: "SELECT plan_hash FROM approvals WHERE id = ?",
      args: [journal.approvalId],
    });
    const hash = result.rows[0]?.plan_hash;
    if (typeof hash !== "string") throw new Error("DEMO_PLAN_HASH_MISSING");
    return hash;
  } finally {
    store.close();
  }
}

/**
 * Seed only tenant-scoped facts owned by this run.  These are deliberately
 * separate from the alert payload so the workflow has to load local authority
 * rather than accepting a self-asserted role change or device claim.
 */
async function seedScenarioBaseline(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  fixture: ReturnType<typeof fixtureForScenario>,
): Promise<void> {
  if (fixture.kind === "unauthorized_privilege_change") {
    await store.execute({
      sql: `INSERT OR IGNORE INTO identity_role_change_authorizations(
        tenant_id, subject_id, source_event_id, actor_id, previous_role,
        current_role, approved, recorded_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
      args: [
        fixture.tenantId,
        fixture.subjectId,
        fixture.sourceEventId,
        fixture.actor.id,
        fixture.changes.previousRole,
        fixture.changes.nextRole,
        DEMO_OCCURRED_AT,
      ],
    });
  }
  if (fixture.kind === "unknown_device_login") {
    // The attacker-controlled presented device is intentionally absent.  A
    // distinct, tenant+subject-scoped enrolled device proves the negative
    // authorization lookup without treating arbitrary IDs as trusted.
    await store.execute({
      sql: `INSERT OR IGNORE INTO authorized_devices(
        id, tenant_id, subject_id, device_id, authorized_at, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [
        demoId("authorized-device", fixture.tenantId),
        fixture.tenantId,
        fixture.subjectId,
        demoId("known-device", fixture.tenantId),
        DEMO_OCCURRED_AT,
        JSON.stringify({ source: "phase9-seed" }),
      ],
    });
  }
}

/** The fake providers read this tenant+incident-scoped authority, never fixture constants. */
async function persistScenarioEvidenceBaseline(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  fixture: ReturnType<typeof fixtureForScenario>,
  incidentId: string,
): Promise<void> {
  const baseline: DemoEvidenceBaseline = {
    version: 1,
    identity: {
      actorId: fixture.actor.id,
      previousRole:
        fixture.kind === "unauthorized_privilege_change"
          ? fixture.changes.previousRole
          : "member",
      currentRole:
        fixture.kind === "unauthorized_privilege_change"
          ? fixture.changes.nextRole
          : "member",
      approved: false,
    },
    cloud: {
      allowedCountry: "US",
      abnormalHistory: false,
      countryByIp:
        fixture.kind === "disallowed_country_login"
          ? { [fixture.ip]: "CA" }
          : {},
    },
    ...(fixture.kind === "unknown_device_login"
      ? {
          device: JSON.parse(
            fixture.changes.signature,
          ) as DemoEvidenceBaseline["device"],
        }
      : {}),
  };
  const snapshot = JSON.stringify(baseline);
  await store.execute({
    sql: `INSERT INTO identity_snapshots(
      id, tenant_id, subject_id, source_event_id, snapshot_json, snapshot_ref,
      integrity_hash, schema_version, captured_at, incident_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    args: [
      demoId("evidence-baseline", fixture.sourceEventId),
      fixture.tenantId,
      fixture.subjectId,
      fixture.sourceEventId,
      snapshot,
      "protected:phase9-demo-evidence-baseline",
      baselineIntegrityHash(baseline),
      DEMO_OCCURRED_AT,
      incidentId,
    ],
  });
}
