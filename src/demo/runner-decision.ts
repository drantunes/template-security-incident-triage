import { createHmac, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import { Hono } from "hono";

import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { registerApprovalRoutes } from "../approval/routes.js";
import { MockDecisionAuthenticator } from "../approval/mock-decision-authenticator.js";
import { createWorkflowApprovalRunReconciler } from "../approval/workflow-resume-reconciler.js";
import { Phase6RecoveryDispatcher } from "../background/phase6-recovery-dispatcher.js";
import { MockIncidentProvider } from "../providers/mock-incident-provider.js";
import { fixedClock } from "../domain/clock.js";
import type { AppEnv } from "../http-context.js";
import { requestContextMiddleware } from "../http-context.js";
import {
  DEMO_EXIT,
  exitForDemoError,
  type DemoJournal,
  type DemoRecord,
} from "./contracts.js";
import { fixtureForScenario, demoId } from "./fixtures.js";
import {
  record,
  refreshDatabaseHash,
  throwIfAborted,
  transition,
} from "./lifecycle-state.js";
import {
  createDemoWorkflow,
  createTracedDemoMastra,
  decisionSecret,
  fixedNow,
  mockState,
  phase6Config,
} from "./runtime.js";
import {
  verifyExpiredTerminal,
  verifyTerminal,
} from "./runner-verification.js";
import type { DemoRunResult, RunOptions } from "./runner-types.js";
import type { StructuredLogger } from "../logging.js";

export async function decideMockDemo(
  root: string,
  initial: DemoJournal,
  decision: "approve" | "reject" | "expire",
  timeoutMs?: number,
  prefix: DemoRecord[] = [],
  signal?: AbortSignal,
  logger: StructuredLogger = { write: () => {} },
  redactionSources?: RunOptions["redactionSources"],
  redactionSourceObserved?: RunOptions["redactionSourceObserved"],
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
  const traceDatabaseUrl = pathToFileURL(initial.traceDatabasePath).href;
  const fixture = fixtureForScenario(initial.scenario, initial.demoRunId);
  const workflow = createDemoWorkflow(
    databaseUrl,
    mockState(initial.scenario, initial.demoRunId),
  );
  let runtime: Awaited<ReturnType<typeof createTracedDemoMastra>> | undefined =
    await createTracedDemoMastra({
      databaseUrl,
      traceDatabaseUrl,
      demoRunId: initial.demoRunId,
      workflow,
    });
  let store: ReturnType<typeof createLibSqlOperationalStore> | undefined =
    createLibSqlOperationalStore({ url: databaseUrl });
  const closeStore = () => {
    const current = store;
    store = undefined;
    current?.close();
  };
  const closeMastra = async () => {
    const current = runtime;
    runtime = undefined;
    if (current) await current.close();
  };
  let journal = initial;
  const app = new Hono<AppEnv>();
  app.use(
    "*",
    requestContextMiddleware(() => demoId("request", initial.demoRunId)),
  );
  registerApprovalRoutes(app, {
    config: phase6Config(),
    store,
    logger,
    authenticator: new MockDecisionAuthenticator({
      mode: "mock",
      enabled: true,
      secret: decisionSecret,
      nowMs: () => Date.parse(fixedNow),
    }),
    reconcileApprovalRun: createWorkflowApprovalRunReconciler(
      runtime!.mastra.getWorkflow("incidentIngestionWorkflow"),
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
        redactionSources,
        redactionSourceObserved,
      ))
    )
      throw new Error("DEMO_DECISION_REJECTED");
    throwIfAborted(signal);
    const verification = await verifyTerminal(
      store,
      journal,
      decision,
      timeoutMs,
      signal,
    );
    if (!verification.ok) throw new Error(verification.code);
    // `verifyTerminal` is the durable terminal marker. Close both the route
    // store and the runtime that resumed it before a fresh semantic snapshot
    // is opened by transition/refreshDatabaseHash.
    closeStore();
    await closeMastra();
    journal = await transition(root, journal, "decided");
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
      closeStore();
    } catch {
      /* closed by an earlier path */
    }
    await closeMastra();
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
    closeStore();
    await closeMastra();
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
  const traceDatabaseUrl = pathToFileURL(initial.traceDatabasePath).href;
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
  let runtime: Awaited<ReturnType<typeof createTracedDemoMastra>> | undefined =
    await createTracedDemoMastra({
      databaseUrl,
      traceDatabaseUrl,
      demoRunId: initial.demoRunId,
      workflow,
    });
  let store: ReturnType<typeof createLibSqlOperationalStore> | undefined =
    createLibSqlOperationalStore({ url: databaseUrl });
  const closeStore = () => {
    const current = store;
    store = undefined;
    current?.close();
  };
  const closeMastra = async () => {
    const current = runtime;
    runtime = undefined;
    if (current) await current.close();
  };
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
        runtime!.mastra.getWorkflow("incidentIngestionWorkflow"),
      ),
    });
    const result = await dispatcher.runOnce();
    if (result.expired !== 1) throw new Error("DEMO_EXPIRY_NOT_OBSERVED");
    throwIfAborted(signal);
    const verification = await verifyExpiredTerminal(store, journal);
    if (!verification.ok) throw new Error(verification.code);
    // The expiry dispatcher has committed its terminal receipt; no runtime or
    // writer may remain when the journal opens a semantic snapshot.
    closeStore();
    await closeMastra();
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
    closeStore();
    await closeMastra();
    journal = await transition(root, journal, "failed");
    return {
      exitCode: exitForDemoError(code),
      journal,
      records: [...prefix, record(journal, "error", { code })],
    };
  } finally {
    closeStore();
    await closeMastra();
  }
}

export async function waitForApproval(
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

async function submitMockDecision(
  app: Hono<AppEnv>,
  journal: DemoJournal,
  tenantId: string,
  decision: "approve" | "reject",
  signal?: AbortSignal,
  redactionSources?: RunOptions["redactionSources"],
  redactionSourceObserved?: RunOptions["redactionSourceObserved"],
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
    ...(redactionSources?.approvalComment
      ? { comment: redactionSources.approvalComment }
      : {}),
    ...(redactionSources?.approvalActor
      ? { actorHint: redactionSources.approvalActor }
      : {}),
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
  if (response.status === 200 && redactionSources?.approvalComment)
    redactionSourceObserved?.("approval-comment");
  if (response.status === 200 && redactionSources?.approvalActor)
    redactionSourceObserved?.("approval-actor");
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
