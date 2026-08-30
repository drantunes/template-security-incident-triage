import { resolve } from "node:path";

import { Mastra } from "@mastra/core/mastra";
import { LibSQLStore } from "@mastra/libsql";
import { afterEach, describe, expect, it } from "vitest";

import {
  authorizeResumeToken,
  decideApprovalAndIssueResumeToken,
} from "../../src/db/approval-operations.js";
import { createIncidentFromAlert } from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import { fixedClock, type Clock } from "../../src/domain/clock.js";
import { sequenceIdGenerator } from "../../src/domain/id-generator.js";
import { createIncidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import { MockCloudEvidenceProvider } from "../../src/providers/cloud-evidence-provider.js";
import { MockEndpointEvidenceProvider } from "../../src/providers/endpoint-evidence-provider.js";
import { MockIdentityEvidenceProvider } from "../../src/providers/identity-evidence-provider.js";
import { MockIncidentProvider } from "../../src/providers/mock-incident-provider.js";
import { Phase6RecoveryDispatcher } from "../../src/background/phase6-recovery-dispatcher.js";
import {
  createApprovalRunReconciler,
  createWorkflowApprovalRunReconciler,
  type ApprovalWorkflow,
} from "../../src/approval/workflow-resume-reconciler.js";
import { expirePendingApproval } from "../../src/db/approval-operations.js";
import { DeterministicRunbookEmbedder } from "../../src/runbooks/embeddings.js";
import { indexRunbook } from "../../src/runbooks/indexer.js";
import { loadRunbooks } from "../../src/runbooks/loader.js";
import { retrieveRunbook } from "../../src/runbooks/retrieve.js";
import { LibSqlRunbookVectorStore } from "../../src/runbooks/vector-store.js";
import { deterministicResponsePlanner } from "../../src/triage/prompt-safe-decision.js";
import type { MockContainmentState } from "../../src/containment/mock-state.js";
import { makeAlert } from "../fixtures/domain.js";
import type { IncidentKind } from "../../src/schemas/incident.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];
const runbookRoot = resolve(process.cwd(), "src/mastra/runbooks");

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("Phase 6 workflow suspend and resume", () => {
  it.each([
    ["unauthorized_privilege_change", "approved"],
    ["unauthorized_privilege_change", "rejected"],
    ["disallowed_country_login", "approved"],
    ["disallowed_country_login", "rejected"],
    ["unknown_device_login", "approved"],
    ["unknown_device_login", "rejected"],
  ] as const)(
    "resumes %s after an authenticated %s decision from durable state",
    async (kind, decision) => {
      const database = await setupDatabase(kind);
      let phase6Now = "2026-08-28T10:01:00.000Z";
      const phase6Clock: Clock = { now: () => phase6Now };
      const state: MockContainmentState = {
        sessions: new Map([["session-1", "active"]]),
        roles: new Map([["subject-1", "admin"]]),
        devices: new Map([["device-new-1", "clear"]]),
        reauthentication: new Map(),
        calls: new Map(),
      };
      const external = new MockIncidentProvider();
      const workflowDefinition = createPhase6Workflow(
        database,
        phase6Clock,
        state,
        external,
      );
      const runtime = new Mastra({
        storage: new LibSQLStore({
          id: `phase6-workflow-${decision}`,
          url: database.url,
        }),
        workflows: { phase6Workflow: workflowDefinition },
      });
      const workflow = runtime.getWorkflow("phase6Workflow");
      const run = await workflow.createRun({ runId: "workflow-run-1" });
      const suspended = await run.start({ inputData: workflowInput });
      expect(suspended.status).toBe("suspended");
      if (suspended.status !== "suspended") return;
      expect(suspended.suspendPayload).toMatchObject({
        "await-approval": {
          incidentId: "incident-1",
          workflowRunId: "workflow-run-1",
          planHashVersion: 1,
        },
      });
      expect(JSON.stringify(suspended.suspendPayload)).not.toMatch(
        /studio-soc-manager|decision|reason|resumeToken/iu,
      );
      const store = database.createStore();
      try {
        const approval = await store.execute({
          sql: `SELECT a.*, i.version FROM approvals a JOIN incidents i
            ON i.tenant_id = a.tenant_id AND i.id = a.incident_id`,
        });
        const row = approval.rows[0]!;
        phase6Now = "2026-08-28T10:02:00.000Z";
        const issued = await decideApprovalAndIssueResumeToken(
          store,
          {
            decision:
              decision === "approved"
                ? {
                    schemaVersion: 1,
                    approvalId: String(row.id),
                    planId: String(row.plan_id),
                    incidentId: "incident-1",
                    tenantId: "tenant-1",
                    planHashVersion: 1,
                    planHash: String(row.plan_hash),
                    decision: "approved",
                    decidedBy: "studio-soc-manager",
                    decidedByRole: "soc_manager",
                    decidedAt: phase6Now,
                  }
                : {
                    schemaVersion: 1,
                    approvalId: String(row.id),
                    planId: String(row.plan_id),
                    incidentId: "incident-1",
                    tenantId: "tenant-1",
                    planHashVersion: 1,
                    planHash: String(row.plan_hash),
                    decision: "rejected",
                    reason: "More evidence is required.",
                    decidedBy: "studio-soc-manager",
                    decidedByRole: "soc_manager",
                    decidedAt: phase6Now,
                  },
            expectedIncidentVersion: Number(row.version),
            runId: "workflow-run-1",
            correlationId: "correlation-1",
            resumeSecret: "resume-secret-".padEnd(40, "x"),
          },
          {
            clock: phase6Clock,
            ids: sequenceIdGenerator(["decision-timeline", "decision-outbox"]),
          },
        );
        phase6Now = "2026-08-28T10:03:00.000Z";
        const authorized = await authorizeResumeToken(
          store,
          {
            token: issued.resumeToken,
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "workflow-run-1",
            approvalId: String(row.id),
          },
          { clock: phase6Clock },
        );
        const resumed = await run.resume({
          step: "await-approval",
          resumeData: { resumeReceiptId: authorized.resumeReceiptId },
        });
        expect(resumed.status).toBe("success");
        const tables = await store.execute({
          sql: `SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
        });
        for (const table of tables.rows) {
          const tableName = String(table.name).replaceAll('"', '""');
          const contents = await store.execute({
            sql: `SELECT * FROM "${tableName}"`,
          });
          expect(JSON.stringify(contents.rows)).not.toContain(
            issued.resumeToken,
          );
        }
        if (resumed.status !== "success") return;
        expect(resumed.result.status).toBe(
          decision === "approved" ? "contained" : "rejected",
        );
        const final = await store.execute({
          sql: `SELECT i.status,
            (SELECT count(*) FROM containment_action_attempts) AS attempts,
            (SELECT count(*) FROM approval_resume_tokens WHERE consumed_at IS NOT NULL) AS consumed
            FROM incidents i WHERE i.id = 'incident-1'`,
        });
        expect(final.rows[0]).toMatchObject({ status: "closed", consumed: 1 });
        if (decision === "approved") {
          expect(Number(final.rows[0]?.attempts)).toBe(2);
          expect(
            [...state.calls.values()].reduce((sum, count) => sum + count, 0),
          ).toBe(2);
        } else {
          expect(Number(final.rows[0]?.attempts)).toBe(0);
          expect(state.calls.size).toBe(0);
        }
      } finally {
        store.close();
      }
    },
  );

  it.each([
    "unauthorized_privilege_change",
    "disallowed_country_login",
    "unknown_device_login",
  ] as const)(
    "expires a suspended %s approval with zero effects",
    async (kind) => {
      const database = await setupDatabase(kind);
      let now = "2026-08-28T10:01:00.000Z";
      const clock: Clock = { now: () => now };
      const state: MockContainmentState = {
        sessions: new Map([["session-1", "active"]]),
        roles: new Map([["subject-1", "admin"]]),
        devices: new Map([["device-new-1", "clear"]]),
        reauthentication: new Map(),
        calls: new Map(),
      };
      const definition = createPhase6Workflow(
        database,
        clock,
        state,
        new MockIncidentProvider(),
      );
      const runtime = new Mastra({
        storage: new LibSQLStore({
          id: `phase6-expiry-${kind}`,
          url: database.url,
        }),
        workflows: { phase6Workflow: definition },
      });
      const workflow = runtime.getWorkflow("phase6Workflow");
      const run = await workflow.createRun({ runId: "workflow-run-1" });
      expect((await run.start({ inputData: workflowInput })).status).toBe(
        "suspended",
      );
      const store = database.createStore();
      try {
        now = "2026-08-28T10:16:00.000Z";
        let terminal: unknown;
        const dispatcher = new Phase6RecoveryDispatcher({
          store,
          provider: new MockIncidentProvider(),
          clock,
          ids: sequenceIdGenerator(["expiry-timeline", "expiry-outbox"]),
          reconcileApprovalRun: async (input) => {
            const result = await createWorkflowApprovalRunReconciler(
              workflow as unknown as ApprovalWorkflow,
            )(input);
            terminal = await workflow.getWorkflowRunById("workflow-run-1", {
              fields: ["result"],
            });
            return result;
          },
        });
        await expect(dispatcher.runOnce()).resolves.toMatchObject({
          expired: 1,
        });
        expect(terminal).toMatchObject({
          status: "success",
          result: { status: "expired" },
        });
        const result = await store.execute({
          sql: `SELECT i.status,
          (SELECT count(*) FROM containment_action_attempts) AS attempts
          FROM incidents i WHERE i.id = 'incident-1'`,
        });
        expect(result.rows[0]).toMatchObject({ status: "failed", attempts: 0 });
        expect(state.calls.size).toBe(0);
      } finally {
        store.close();
      }
    },
  );

  it("reconciles an expiry after resume completed but before its marker was stored", async () => {
    const database = await setupDatabase("unauthorized_privilege_change");
    let now = "2026-08-28T10:01:00.000Z";
    const clock: Clock = { now: () => now };
    const state: MockContainmentState = {
      sessions: new Map([["session-1", "active"]]),
      roles: new Map([["subject-1", "admin"]]),
      devices: new Map(),
      reauthentication: new Map(),
      calls: new Map(),
    };
    const definition = createPhase6Workflow(
      database,
      clock,
      state,
      new MockIncidentProvider(),
    );
    const runtime = new Mastra({
      storage: new LibSQLStore({
        id: "phase6-expiry-reconcile",
        url: database.url,
      }),
      workflows: { phase6Workflow: definition },
    });
    const workflow = runtime.getWorkflow("phase6Workflow");
    const run = await workflow.createRun({ runId: "workflow-run-1" });
    expect((await run.start({ inputData: workflowInput })).status).toBe(
      "suspended",
    );
    const store = database.createStore();
    try {
      const approval = await store.execute({
        sql: "SELECT id FROM approvals WHERE incident_id = 'incident-1'",
      });
      const approvalId = String(approval.rows[0]?.id);
      now = "2026-08-28T10:16:00.000Z";
      await expirePendingApproval(
        store,
        {
          tenantId: "tenant-1",
          incidentId: "incident-1",
          approvalId,
          workflowRunId: "workflow-run-1",
          correlationId: "expiry-reconcile",
        },
        {
          clock,
          ids: sequenceIdGenerator(["expiry-timeline", "expiry-outbox"]),
        },
      );
      let resumeCalls = 0;
      const reconciler = createApprovalRunReconciler({
        read: (workflowRunId) =>
          workflow.getWorkflowRunById(workflowRunId, {
            fields: ["steps", "result"],
          }),
        resume: async ({ resumeReceiptId }) => {
          resumeCalls += 1;
          return run.resume({
            step: "await-approval",
            resumeData: { resumeReceiptId },
          });
        },
      });
      await expect(
        reconciler({
          workflowRunId: "workflow-run-1",
          resumeReceiptId: `expiry_${approvalId}`,
          expectedResultStatuses: ["expired"],
        }),
      ).resolves.toBe("completed");
      expect(resumeCalls).toBe(1);
      const beforeRestart = await store.execute({
        sql: "SELECT expiry_resumed_at FROM approvals WHERE id = ?",
        args: [approvalId],
      });
      expect(beforeRestart.rows[0]?.expiry_resumed_at).toBeNull();
      const restarted = new Phase6RecoveryDispatcher({
        store,
        provider: new MockIncidentProvider(),
        clock,
        reconcileApprovalRun: reconciler,
      });
      await expect(restarted.runOnce()).resolves.toMatchObject({ expired: 1 });
      expect(resumeCalls).toBe(1);
      const marked = await store.execute({
        sql: "SELECT expiry_resumed_at FROM approvals WHERE id = ?",
        args: [approvalId],
      });
      expect(marked.rows[0]?.expiry_resumed_at).toBe(now);
    } finally {
      store.close();
    }
  });

  it("reconciles a decided run after resume completed but before token marking", async () => {
    const database = await setupDatabase("unauthorized_privilege_change");
    let now = "2026-08-28T10:01:00.000Z";
    const clock: Clock = { now: () => now };
    const state: MockContainmentState = {
      sessions: new Map([["session-1", "active"]]),
      roles: new Map([["subject-1", "admin"]]),
      devices: new Map(),
      reauthentication: new Map(),
      calls: new Map(),
    };
    const definition = createPhase6Workflow(
      database,
      clock,
      state,
      new MockIncidentProvider(),
    );
    const runtime = new Mastra({
      storage: new LibSQLStore({
        id: "phase6-decision-reconcile",
        url: database.url,
      }),
      workflows: { phase6Workflow: definition },
    });
    const workflow = runtime.getWorkflow("phase6Workflow");
    const run = await workflow.createRun({ runId: "workflow-run-1" });
    expect((await run.start({ inputData: workflowInput })).status).toBe(
      "suspended",
    );
    const store = database.createStore();
    try {
      const current = await store.execute({
        sql: `SELECT i.version, a.id, a.plan_id, a.plan_hash
          FROM incidents i JOIN approvals a
            ON a.tenant_id = i.tenant_id AND a.incident_id = i.id
          WHERE i.id = 'incident-1'`,
      });
      const row = current.rows[0]!;
      now = "2026-08-28T10:02:00.000Z";
      const issued = await decideApprovalAndIssueResumeToken(
        store,
        {
          decision: {
            schemaVersion: 1,
            approvalId: String(row.id),
            planId: String(row.plan_id),
            incidentId: "incident-1",
            tenantId: "tenant-1",
            planHashVersion: 1,
            planHash: String(row.plan_hash),
            decision: "rejected",
            reason: "More evidence is required.",
            decidedBy: "studio-soc-manager",
            decidedByRole: "soc_manager",
            decidedAt: now,
          },
          expectedIncidentVersion: Number(row.version),
          runId: "workflow-run-1",
          correlationId: "decision-reconcile",
          resumeSecret: "resume-secret-".padEnd(40, "x"),
        },
        {
          clock,
          ids: sequenceIdGenerator(["decision-timeline", "decision-outbox"]),
        },
      );
      const authorized = await authorizeResumeToken(
        store,
        {
          token: issued.resumeToken,
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "workflow-run-1",
          approvalId: String(row.id),
        },
        { clock },
      );
      let resumeCalls = 0;
      const reconciler = createApprovalRunReconciler({
        read: (workflowRunId) =>
          workflow.getWorkflowRunById(workflowRunId, {
            fields: ["steps", "result"],
          }),
        resume: async ({ resumeReceiptId }) => {
          resumeCalls += 1;
          return run.resume({
            step: "await-approval",
            resumeData: { resumeReceiptId },
          });
        },
      });
      await expect(
        reconciler({
          workflowRunId: "workflow-run-1",
          resumeReceiptId: authorized.resumeReceiptId,
          expectedResultStatuses: ["rejected"],
        }),
      ).resolves.toBe("completed");
      expect(resumeCalls).toBe(1);
      const unmarked = await store.execute({
        sql: "SELECT resumed_at FROM approval_resume_tokens WHERE id = ?",
        args: [authorized.resumeReceiptId],
      });
      expect(unmarked.rows[0]?.resumed_at).toBeNull();
      const restarted = new Phase6RecoveryDispatcher({
        store,
        provider: new MockIncidentProvider(),
        clock,
        reconcileApprovalRun: reconciler,
      });
      await expect(restarted.runOnce()).resolves.toMatchObject({ resumed: 1 });
      expect(resumeCalls).toBe(1);
      const marked = await store.execute({
        sql: "SELECT resumed_at FROM approval_resume_tokens WHERE id = ?",
        args: [authorized.resumeReceiptId],
      });
      expect(marked.rows[0]?.resumed_at).toBe(now);
    } finally {
      store.close();
    }
  });
});

async function setupDatabase(kind: IncidentKind) {
  const database = await createTempDatabase();
  databases.push(database);
  const store = database.createStore();
  await migrateOperationalStore(store);
  const vector = new LibSqlRunbookVectorStore({ url: database.url });
  try {
    for (const [index, runbook] of (
      await loadRunbooks(runbookRoot)
    ).entries()) {
      await indexRunbook(
        store,
        vector,
        new DeterministicRunbookEmbedder(),
        runbook,
        {
          generationId: `phase6-generation-${index + 1}`,
          now: "2026-08-28T09:59:00.000Z",
        },
      );
    }
    await createIncidentFromAlert(
      store,
      makeAlert({
        kind,
        sessionId: "session-1",
        ...(kind === "unknown_device_login"
          ? { deviceId: "device-new-1" }
          : {}),
        ...(kind === "disallowed_country_login" ? { ip: "198.51.100.8" } : {}),
      }),
      {
        clock: fixedClock("2026-08-28T10:00:00.000Z"),
        ids: sequenceIdGenerator(["incident-1", "timeline-1", "outbox-1"]),
      },
    );
  } finally {
    store.close();
    await vector.close();
  }
  return database;
}

function createPhase6Workflow(
  database: TempDatabase,
  clock: Clock,
  state: MockContainmentState,
  provider: MockIncidentProvider,
) {
  return createIncidentIngestionWorkflow(
    () => database.createStore(),
    {
      openVectorStore: () =>
        new LibSqlRunbookVectorStore({ url: database.url }),
      embedder: new DeterministicRunbookEmbedder(),
      retrieve: (store, vector, embedder, input) =>
        retrieveRunbook(store, vector, embedder, input, {
          threshold: -1,
          topK: 3,
          clock: fixedClock("2026-08-28T10:00:45.000Z"),
        }),
    },
    {
      identityProvider: new MockIdentityEvidenceProvider(),
      endpointProvider: new MockEndpointEvidenceProvider({
        verifyDeviceSignature: (input) => input.deviceId === "device-new-1",
      }),
      cloudProvider: new MockCloudEvidenceProvider(),
      clock: fixedClock("2026-08-28T10:00:30.000Z"),
      supervisor: async () => ({
        scopeValidated: true,
        specialists: ["identity", "endpoint", "cloud"],
      }),
      identityInvestigator: deterministicInvestigator,
      endpointInvestigator: deterministicInvestigator,
      cloudInvestigator: deterministicInvestigator,
      correlationAnalyst: async ({ candidate }) => candidate,
    },
    { planner: deterministicResponsePlanner, runbookRoot },
    {
      enabled: true,
      provider,
      state,
      mode: "mock",
      timeoutMs: 1_000,
      rateLimit: 8,
      clock,
    },
  );
}

const workflowInput = {
  eventId: "workflow-run-1",
  incidentId: "incident-1",
  tenantId: "tenant-1",
  alertId: "alert-1",
  correlationId: "correlation-1",
};

const deterministicInvestigator = async (input: {
  facts: readonly { factToken: string }[];
}) => ({
  citedFactTokens: input.facts.map((fact) => fact.factToken),
  gaps: [],
  contradictionFlags: [],
});
