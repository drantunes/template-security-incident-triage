import { createHash, createHmac } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

import { EventEmitterPubSub } from "@mastra/core/events";
import { LibSQLStore } from "@mastra/libsql";
import { Mastra } from "@mastra/core/mastra";
import { Hono } from "hono";

import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { migrateOperationalStore } from "../db/migrate.js";
import { registerWebhookRoutes } from "../webhooks/routes.js";
import { OutboxDispatcher } from "../background/outbox-dispatcher.js";
import { startWorkflowWorker } from "../background/workflow-worker.js";
import type { AppEnv } from "../http-context.js";
import { LibSqlRunbookVectorStore } from "../runbooks/vector-store.js";
import { DeterministicRunbookEmbedder } from "../runbooks/embeddings.js";
import { indexRunbook } from "../runbooks/indexer.js";
import { loadRunbooks } from "../runbooks/loader.js";
import { DEMO_EXIT, exitForDemoError, type DemoRecord } from "./contracts.js";
import { demoId, fixtureForScenario } from "./fixtures.js";
import {
  demoRoot,
  newJournal,
  readJournal,
  reserveOwnedDatabase,
  resourceHash,
  writeJournal,
} from "./journal.js";
import { preflightDemo } from "./preflight.js";
import { decideMockDemo } from "./runner-decision.js";
import {
  verifyExpiredTerminal,
  verifyTerminal,
} from "./runner-verification.js";
import {
  persistScenarioEvidenceBaseline,
  seedScenarioBaseline,
} from "./seed-baseline.js";
import {
  createDemoWorkflow,
  fixedNow,
  mockState,
  phase2Config,
  shutdownDemoMastra,
  webhookSecret,
} from "./runtime.js";
import {
  pendingDatabasePrecondition,
  record,
  refreshDatabaseHash,
  reservedDatabasePrecondition,
  throwIfAborted,
  throwIfDeadlineExceeded,
  transition,
} from "./lifecycle-state.js";
import { waitForApproval } from "./runner-decision.js";
import type { DemoRunResult, RunOptions } from "./runner-types.js";

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
    const signature = createHmac("sha256", webhookSecret)
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
