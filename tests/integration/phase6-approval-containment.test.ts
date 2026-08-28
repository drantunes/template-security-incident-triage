import { createHmac } from "node:crypto";
import { Hono } from "hono";
import { afterEach, describe, expect, it } from "vitest";

import {
  consumeResumeToken,
  decideApprovalAndIssueResumeToken,
  expirePendingApproval,
  requestApproval,
} from "../../src/db/approval-operations.js";
import {
  createIncidentFromAlert,
  transitionIncident,
} from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import { fixedClock, type Clock } from "../../src/domain/clock.js";
import { sequenceIdGenerator } from "../../src/domain/id-generator.js";
import { ContainmentGateway } from "../../src/containment/gateway.js";
import type { MockContainmentState } from "../../src/containment/mock-state.js";
import { deliverExternalIncident } from "../../src/db/provider-delivery-operations.js";
import { MockIncidentProvider } from "../../src/providers/mock-incident-provider.js";
import {
  ExternalIncidentProjectionSchema,
  type IncidentProvider,
} from "../../src/providers/incident-provider.js";
import { registerApprovalRoutes } from "../../src/approval/routes.js";
import { MockDecisionAuthenticator } from "../../src/approval/mock-decision-authenticator.js";
import { Phase6RecoveryDispatcher } from "../../src/background/phase6-recovery-dispatcher.js";
import { retryPartialContainment } from "../../src/containment/partial-retry.js";
import { recordContainmentOutcome } from "../../src/db/containment-outcome-operations.js";
import { createFinalizeIncidentStep } from "../../src/mastra/steps/finalize-incident.js";
import { ContainmentExecutionResultSchema } from "../../src/approval/phase6-contracts.js";
import type { OperationalStore } from "../../src/db/operational-store.js";
import type { AppEnv } from "../../src/http-context.js";
import type { Phase6Config } from "../../src/env.js";
import {
  makeAlert,
  makeApprovalRequest,
  makePlan,
  seedAuthoritativePhase5Result,
} from "../fixtures/domain.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

async function setup(plan = makePlan()) {
  const database = await createTempDatabase();
  databases.push(database);
  const store = database.createStore();
  await migrateOperationalStore(store);
  await createIncidentFromAlert(store, makeAlert(), {
    clock: fixedClock("2026-08-27T12:00:00.000Z"),
    ids: sequenceIdGenerator(["incident-1", "timeline-1", "outbox-1"]),
  });
  await transitionIncident(
    store,
    {
      tenantId: "tenant-1",
      incidentId: "incident-1",
      expectedVersion: 0,
      to: "investigating",
      runId: "run-1",
      correlationId: "correlation-1",
    },
    {
      clock: fixedClock("2026-08-27T12:00:30.000Z"),
      ids: sequenceIdGenerator(["timeline-2", "outbox-2"]),
    },
  );
  await store.execute({
    sql: `INSERT INTO workflow_runs(
      id, incident_id, tenant_id, run_id, workflow_id, status, started_at
    ) VALUES ('workflow-row-1', 'incident-1', 'tenant-1', 'run-1',
      'incident-ingestion-workflow', 'running', '2026-08-27T12:00:30.000Z')`,
  });
  await store.execute({
    sql: `UPDATE incidents SET current_run_id = 'run-1'
      WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
  });
  await seedAuthoritativePhase5Result(store, plan);
  const approval = makeApprovalRequest({
    planId: plan.planId,
    planHash: plan.planHash,
    expiresAt: plan.expiresAt,
  });
  await requestApproval(
    store,
    {
      plan,
      approval,
      expectedIncidentVersion: 1,
      runId: "run-1",
      correlationId: "correlation-1",
    },
    {
      clock: fixedClock("2026-08-27T12:01:00.000Z"),
      ids: sequenceIdGenerator([
        ...plan.actions.map((_, index) => `action-row-${index + 1}`),
        "timeline-3",
        "outbox-3",
      ]),
    },
  );
  return { database, store, plan, approval };
}

async function setupAdditionalApprovedIncident(
  store: Awaited<ReturnType<typeof setup>>["store"],
  actionType: "restore_previous_role" | "revoke_session",
) {
  const baseAction = makePlan().actions[0]!;
  const actionInput: Record<string, string | number | boolean | null> =
    actionType === "revoke_session" ? {} : { role: "member" };
  const action = {
    ...baseAction,
    actionId: "action-2",
    type: actionType,
    targetId: actionType === "revoke_session" ? "session-2" : "subject-2",
    input: actionInput,
  };
  const plan = makePlan({
    planId: "plan-2",
    incidentId: "incident-2",
    actions: [action],
  });
  await createIncidentFromAlert(
    store,
    makeAlert({
      alertId: "alert-2",
      sourceEventId: "source-event-2",
      subjectId: "subject-2",
      target: { id: "subject-2", type: "user" },
      rawPayloadRef: "protected://alerts/2",
      idempotencyKey: "alert-idempotency-2",
    }),
    {
      clock: fixedClock("2026-08-27T12:00:00.000Z"),
      ids: sequenceIdGenerator([
        "incident-2",
        "timeline-incident-2",
        "outbox-incident-2",
      ]),
    },
  );
  await transitionIncident(
    store,
    {
      tenantId: "tenant-1",
      incidentId: "incident-2",
      expectedVersion: 0,
      to: "investigating",
      runId: "run-2",
      correlationId: "correlation-2",
    },
    {
      clock: fixedClock("2026-08-27T12:00:30.000Z"),
      ids: sequenceIdGenerator([
        "timeline-investigating-2",
        "outbox-investigating-2",
      ]),
    },
  );
  await store.execute({
    sql: `INSERT INTO workflow_runs(
      id, incident_id, tenant_id, run_id, workflow_id, status, started_at
    ) VALUES ('workflow-row-2', 'incident-2', 'tenant-1', 'run-2',
      'incident-ingestion-workflow', 'running', '2026-08-27T12:00:30.000Z')`,
  });
  await store.execute({
    sql: `UPDATE incidents SET current_run_id = 'run-2'
      WHERE tenant_id = 'tenant-1' AND id = 'incident-2'`,
  });
  await seedAuthoritativePhase5Result(store, plan, "run-2");
  await requestApproval(
    store,
    {
      plan,
      approval: makeApprovalRequest({
        approvalId: "approval-2",
        planId: plan.planId,
        incidentId: plan.incidentId,
        planHash: plan.planHash,
        expiresAt: plan.expiresAt,
      }),
      expectedIncidentVersion: 1,
      runId: "run-2",
      correlationId: "correlation-2",
    },
    {
      clock: fixedClock("2026-08-27T12:01:00.000Z"),
      ids: sequenceIdGenerator([
        "action-row-2",
        "timeline-approval-2",
        "outbox-approval-2",
      ]),
    },
  );
  await decideApprovalAndIssueResumeToken(
    store,
    {
      decision: {
        schemaVersion: 1,
        approvalId: "approval-2",
        planId: plan.planId,
        incidentId: plan.incidentId,
        tenantId: plan.tenantId,
        planHashVersion: 1,
        planHash: plan.planHash,
        decision: "approved",
        decidedBy: "studio-soc-manager",
        decidedByRole: "soc_manager",
        decidedAt: "2026-08-27T12:02:00.000Z",
      },
      expectedIncidentVersion: 2,
      runId: "run-2",
      correlationId: "correlation-2",
      resumeSecret: "resume-secret-".padEnd(40, "x"),
    },
    {
      clock: fixedClock("2026-08-27T12:02:00.000Z"),
      ids: sequenceIdGenerator(["timeline-decision-2", "outbox-decision-2"]),
    },
  );
  return { plan, action };
}

function schemaValidPlanTamperings(plan: ReturnType<typeof makePlan>) {
  const [action, ...remainingActions] = plan.actions;
  if (!action) throw new Error("fixture plan must contain an action");
  return [
    {
      ...plan,
      actions: [
        { ...action, actionId: `${action.actionId}-tampered` },
        ...remainingActions,
      ],
    },
    {
      ...plan,
      actions: [
        { ...action, targetId: `${action.targetId}-tampered` },
        ...remainingActions,
      ],
    },
    {
      ...plan,
      actions: [
        { ...action, input: { ...action.input, role: "viewer" } },
        ...remainingActions,
      ],
    },
  ];
}

async function approve(
  store: Awaited<ReturnType<typeof setup>>["store"],
  plan = makePlan(),
) {
  return decideApprovalAndIssueResumeToken(
    store,
    {
      decision: {
        schemaVersion: 1,
        approvalId: "approval-1",
        planId: plan.planId,
        incidentId: "incident-1",
        tenantId: "tenant-1",
        planHashVersion: 1,
        planHash: plan.planHash,
        decision: "approved",
        decidedBy: "studio-soc-manager",
        decidedByRole: "soc_manager",
        decidedAt: "2026-08-27T12:02:00.000Z",
      },
      expectedIncidentVersion: 2,
      runId: "run-1",
      correlationId: "correlation-1",
      resumeSecret: "resume-secret-".padEnd(40, "x"),
    },
    {
      clock: fixedClock("2026-08-27T12:02:00.000Z"),
      ids: sequenceIdGenerator(["timeline-4", "outbox-4"]),
    },
  );
}

async function preparePartialContainmentFailure(
  store: Awaited<ReturnType<typeof setup>>["store"],
  plan: ReturnType<typeof makePlan>,
) {
  const [first, second] = plan.actions;
  if (!first || !second) throw new Error("fixture plan must have two actions");
  await approve(store, plan);
  await transitionIncident(
    store,
    {
      tenantId: "tenant-1",
      incidentId: "incident-1",
      expectedVersion: 3,
      to: "containing",
      runId: "run-1",
      correlationId: "correlation-1",
      causationId: "approval-1",
    },
    {
      clock: fixedClock("2026-08-27T12:03:00.000Z"),
      ids: sequenceIdGenerator(["containing-timeline", "containing-outbox"]),
    },
  );
  const state = mockState();
  state.roles.set("subject-1", "admin");
  state.sessions.set("session-1", "active");
  state.failActions = new Set([second.actionId]);
  const gateway = gatewayFor(store, state);
  await gateway.executeApprovedAction({
    tenantId: "tenant-1",
    incidentId: "incident-1",
    workflowRunId: "run-1",
    approvalId: "approval-1",
    plan,
    action: first,
  });
  await gateway.executeApprovedAction({
    tenantId: "tenant-1",
    incidentId: "incident-1",
    workflowRunId: "run-1",
    approvalId: "approval-1",
    plan,
    action: second,
  });
  await recordContainmentOutcome(
    store,
    {
      tenantId: "tenant-1",
      incidentId: "incident-1",
      workflowRunId: "run-1",
      correlationId: "correlation-1",
      approvalId: "approval-1",
      expectedVersion: 4,
      status: "failed",
      partial: true,
      completedCount: 1,
      failedCount: 1,
    },
    {
      clock: fixedClock("2026-08-27T12:03:00.000Z"),
      ids: sequenceIdGenerator(["failed-timeline", "failed-outbox"]),
    },
  );
  state.failActions.clear();
  return { first, second, state };
}

async function reject(
  store: Awaited<ReturnType<typeof setup>>["store"],
  plan = makePlan(),
) {
  return decideApprovalAndIssueResumeToken(
    store,
    {
      decision: {
        schemaVersion: 1,
        approvalId: "approval-1",
        planId: plan.planId,
        incidentId: "incident-1",
        tenantId: "tenant-1",
        planHashVersion: 1,
        planHash: plan.planHash,
        decision: "rejected",
        reason: "manager rejected containment",
        decidedBy: "studio-soc-manager",
        decidedByRole: "soc_manager",
        decidedAt: "2026-08-27T12:02:00.000Z",
      },
      expectedIncidentVersion: 2,
      runId: "run-1",
      correlationId: "correlation-1",
      resumeSecret: "resume-secret-".padEnd(40, "x"),
    },
    {
      clock: fixedClock("2026-08-27T12:02:00.000Z"),
      ids: sequenceIdGenerator(["timeline-4", "outbox-4"]),
    },
  );
}

async function readPhase5Payload(store: OperationalStore) {
  const result = await store.execute({
    sql: `SELECT phase5_result_json FROM workflow_runs WHERE run_id = 'run-1'`,
  });
  return JSON.parse(String(result.rows[0]?.phase5_result_json)) as {
    decision: unknown;
    summary: unknown;
  };
}

describe("Phase 6 durable approval and containment", () => {
  it("rejects a self-consistent plan that diverges from the authoritative Phase 5 result or TTL", async () => {
    const { store } = await setup();
    try {
      const longLived = makePlan({
        planId: "plan-long-lived",
        expiresAt: "2026-08-28T12:01:00.000Z",
      });
      await expect(
        requestApproval(
          store,
          {
            plan: longLived,
            approval: makeApprovalRequest({
              approvalId: "approval-long-lived",
              planId: longLived.planId,
              planHash: longLived.planHash,
              expiresAt: longLived.expiresAt,
            }),
            expectedIncidentVersion: 2,
            runId: "run-1",
            correlationId: "correlation-1",
          },
          { clock: fixedClock("2026-08-27T12:02:00.000Z") },
        ),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });

      const changed = makePlan({
        planId: "plan-changed",
        actions: [
          {
            ...makePlan().actions[0]!,
            actionId: "action-changed",
            targetId: "subject-2",
          },
        ],
      });
      await expect(
        requestApproval(
          store,
          {
            plan: changed,
            approval: makeApprovalRequest({
              approvalId: "approval-changed",
              planId: changed.planId,
              planHash: changed.planHash,
            }),
            expectedIncidentVersion: 2,
            runId: "run-1",
            correlationId: "correlation-1",
          },
          { clock: fixedClock("2026-08-27T12:02:00.000Z") },
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });
    } finally {
      store.close();
    }
  });

  it("closes an expired pending approval as failed with zero containment attempts", async () => {
    const { store } = await setup();
    try {
      await expect(
        expirePendingApproval(
          store,
          {
            tenantId: "tenant-1",
            incidentId: "incident-1",
            approvalId: "approval-1",
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          {
            clock: fixedClock("2026-08-27T13:00:00.000Z"),
            ids: sequenceIdGenerator(["timeline-expired", "outbox-expired"]),
          },
        ),
      ).resolves.toBe(true);
      const state = await store.execute({
        sql: `SELECT i.status,
          (SELECT count(*) FROM containment_action_attempts) AS attempts,
          (SELECT count(*) FROM timeline_events WHERE type = 'approval.expired') AS expiry_events
          FROM incidents i WHERE i.id = 'incident-1'`,
      });
      expect(state.rows[0]).toEqual({
        status: "failed",
        attempts: 0,
        expiry_events: 1,
      });
    } finally {
      store.close();
    }
  });

  it("retries expiry resume after a process failure following the expiry commit", async () => {
    const { store } = await setup();
    try {
      const clock = fixedClock("2026-08-27T13:00:00.000Z");
      const first = new Phase6RecoveryDispatcher({
        store,
        provider: new MockIncidentProvider(),
        clock,
        ids: sequenceIdGenerator(["expiry-timeline", "expiry-outbox"]),
        reconcileApprovalRun: async () => {
          throw new Error("process stopped before workflow resume");
        },
      });
      await expect(first.runOnce()).rejects.toThrow(
        "process stopped before workflow resume",
      );
      const committed = await store.execute({
        sql: `SELECT i.status, a.expiry_resumed_at FROM incidents i
          JOIN approvals a ON a.tenant_id = i.tenant_id AND a.incident_id = i.id`,
      });
      expect(committed.rows[0]).toEqual({
        status: "failed",
        expiry_resumed_at: null,
      });
      let resumed = 0;
      const restarted = new Phase6RecoveryDispatcher({
        store,
        provider: new MockIncidentProvider(),
        clock,
        reconcileApprovalRun: async () => {
          resumed += 1;
          return "completed";
        },
      });
      await expect(restarted.runOnce()).resolves.toMatchObject({ expired: 1 });
      expect(resumed).toBe(1);
      const marker = await store.execute({
        sql: "SELECT expiry_resumed_at FROM approvals",
      });
      expect(marker.rows[0]?.expiry_resumed_at).toBe(
        "2026-08-27T13:00:00.000Z",
      );
    } finally {
      store.close();
    }
  });

  it("decides through the authenticated route without returning the resume token", async () => {
    const { store, plan } = await setup();
    try {
      const app = new Hono<AppEnv>();
      app.use("*", async (context, next) => {
        context.set("requestId", "request-1");
        context.set("correlationId", "correlation-1");
        await next();
      });
      const timestamp = Date.parse("2026-08-27T12:02:00.000Z");
      const secret = "decision-secret-".padEnd(40, "x");
      const resumed: Array<{
        workflowRunId: string;
        resumeReceiptId: string;
      }> = [];
      const config: Phase6Config = {
        mode: "mock",
        mockDecisionsEnabled: true,
        mockDecisionSecret: secret,
        approvalResumeSecret: "resume-secret-".padEnd(40, "x"),
        actionTimeoutMs: 1_000,
        rateLimit: 8,
      };
      registerApprovalRoutes(app, {
        config,
        store,
        logger: { write: () => {} },
        authenticator: new MockDecisionAuthenticator({
          mode: "mock",
          enabled: true,
          secret,
          nowMs: () => timestamp,
        }),
        reconcileApprovalRun: async (input) => {
          resumed.push(input);
          return "completed";
        },
        clock: fixedClock("2026-08-27T12:02:00.000Z"),
      });
      const path = "/api/incidents/incident-1/approvals/approval-1/decision";
      const body = JSON.stringify({
        decision: "approved",
        planId: plan.planId,
        planHashVersion: 1,
        planHash: plan.planHash,
      });
      const nonce = "route-nonce-1234567890";
      const signature = createHmac("sha256", secret)
        .update(`${timestamp}.${nonce}.POST.${path}.`)
        .update("tenant-1.")
        .update(body)
        .digest("hex");
      const response = await app.request(path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Decision-Signature": `t=${timestamp},v1=${signature}`,
          "X-Decision-Nonce": nonce,
          "X-Decision-Tenant": "tenant-1",
        },
        body,
      });
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json).toMatchObject({ decision: "approved", resumed: true });
      expect(JSON.stringify(json)).not.toContain("resumeToken");
      expect(resumed).toHaveLength(1);
      expect(resumed[0]!.workflowRunId).toBe("run-1");
    } finally {
      store.close();
    }
  });

  it("stores only a token digest, consumes it once, and rejects stolen/replayed tokens", async () => {
    const { store } = await setup();
    try {
      const issued = await approve(store);
      const persisted = await store.execute({
        sql: "SELECT token_digest, consumed_at FROM approval_resume_tokens",
      });
      expect(persisted.rows[0]?.token_digest).toMatch(/^[a-f0-9]{64}$/u);
      expect(JSON.stringify(persisted.rows)).not.toContain(issued.resumeToken);
      await expect(
        consumeResumeToken(
          store,
          {
            token: issued.resumeToken,
            tenantId: "tenant-2",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
          },
          { clock: fixedClock("2026-08-27T12:03:00.000Z") },
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      await expect(
        consumeResumeToken(
          store,
          {
            token: issued.resumeToken,
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
          },
          { clock: fixedClock("2026-08-27T12:03:00.000Z") },
        ),
      ).resolves.toMatchObject({
        decision: "approved",
        decidedByRole: "soc_manager",
      });
      await expect(
        consumeResumeToken(
          store,
          {
            token: issued.resumeToken,
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
          },
          { clock: fixedClock("2026-08-27T12:04:00.000Z") },
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });
    } finally {
      store.close();
    }
  });

  it("replays the persisted decision timestamp without issuing a different token", async () => {
    const { store, plan } = await setup();
    try {
      const first = await approve(store, plan);
      const replay = await decideApprovalAndIssueResumeToken(
        store,
        {
          decision: {
            ...first.decision,
            decidedAt: "2026-08-27T12:03:00.000Z",
          },
          expectedIncidentVersion: 3,
          runId: "run-1",
          correlationId: "correlation-replay",
          resumeSecret: "resume-secret-".padEnd(40, "x"),
        },
        { clock: fixedClock("2026-08-27T12:03:00.000Z") },
      );
      expect(replay.decision.decidedAt).toBe("2026-08-27T12:02:00.000Z");
      expect(replay.resumeToken).toBe(first.resumeToken);
    } finally {
      store.close();
    }
  });

  it("rejects cross-bound token and action-attempt ledger rows at the database boundary", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const approval = await store.execute({
        sql: `SELECT decision_fingerprint, expires_at FROM approvals
          WHERE id = 'approval-1'`,
      });
      await expect(
        store.execute({
          sql: `INSERT INTO approval_resume_tokens(
            id, tenant_id, incident_id, workflow_run_id, approval_id, decision,
            decision_fingerprint, digest_version, token_digest, issued_at, expires_at
          ) VALUES ('wrong-run-token', 'tenant-1', 'incident-1', 'run-other',
            'approval-1', 'approved', ?, 1, ?,
            '2026-08-27T12:02:00.000Z', ?)`,
          args: [
            String(approval.rows[0]!.decision_fingerprint),
            "f".repeat(64),
            String(approval.rows[0]!.expires_at),
          ],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `INSERT INTO containment_action_attempts(
            id, tenant_id, incident_id, plan_id, approval_id, action_id,
            idempotency_key, attempt, owner_id, fence_token, status,
            started_at, finished_at, lease_expires_at, verification, error_code
          ) VALUES ('wrong-action-attempt', 'tenant-1', 'incident-1', ?,
            'approval-1', 'action-not-in-plan', 'wrong-key', 1, 'run-1',
            'wrong-fence', 'failed', '2026-08-27T12:03:00.000Z',
            '2026-08-27T12:03:00.000Z', '2026-08-27T12:04:00.000Z',
            'not_run', 'PROVIDER_FAILED')`,
          args: [plan.planId],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
    } finally {
      store.close();
    }
  });

  it("makes rejection authoritative while executing zero containment actions", async () => {
    const { store, plan } = await setup();
    try {
      const rejected = await decideApprovalAndIssueResumeToken(
        store,
        {
          decision: {
            schemaVersion: 1,
            approvalId: "approval-1",
            planId: plan.planId,
            incidentId: "incident-1",
            tenantId: "tenant-1",
            planHashVersion: 1,
            planHash: plan.planHash,
            decision: "rejected",
            reason: "Additional evidence is required.",
            decidedBy: "studio-soc-manager",
            decidedByRole: "soc_manager",
            decidedAt: "2026-08-27T12:02:00.000Z",
          },
          expectedIncidentVersion: 2,
          runId: "run-1",
          correlationId: "correlation-1",
          resumeSecret: "resume-secret-".padEnd(40, "x"),
        },
        {
          clock: fixedClock("2026-08-27T12:02:00.000Z"),
          ids: sequenceIdGenerator(["timeline-rejected", "outbox-rejected"]),
        },
      );
      await expect(
        consumeResumeToken(
          store,
          {
            token: rejected.resumeToken,
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
          },
          { clock: fixedClock("2026-08-27T12:03:00.000Z") },
        ),
      ).resolves.toMatchObject({ decision: "rejected" });
      const state = mockState();
      await expect(
        gatewayFor(store, state).executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan,
          action: plan.actions[0]!,
        }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
      const count = await store.execute({
        sql: "SELECT count(*) AS count FROM containment_action_attempts",
      });
      expect(Number(count.rows[0]?.count)).toBe(0);
      expect(state.calls.size).toBe(0);
    } finally {
      store.close();
    }
  });

  it("executes through the gateway once and rejects tampering/non-mock mode", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      const gateway = gatewayFor(store, state);
      const input = {
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: plan.actions[0]!,
      };
      const concurrent = await Promise.allSettled([
        gateway.executeApprovedAction(input),
        gateway.executeApprovedAction(input),
      ]);
      expect(
        concurrent.some(
          (result) =>
            result.status === "fulfilled" &&
            result.value.status === "completed",
        ),
      ).toBe(true);
      await expect(gateway.executeApprovedAction(input)).resolves.toMatchObject(
        {
          status: "completed",
          verification: "verified",
        },
      );
      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      await expect(
        gateway.executeApprovedAction({
          ...input,
          action: { ...plan.actions[0]!, targetId: "subject-2" },
        }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
      await expect(
        gatewayFor(store, state, "staging").executeApprovedAction(input),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    } finally {
      store.close();
    }
  });

  it("blocks a changed precondition before the mock provider effect", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "owner");
      const result = await gatewayFor(store, state).executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: plan.actions[0]!,
      });
      expect(result).toMatchObject({
        status: "blocked",
        errorCode: "PRECONDITION_FAILED",
      });
      expect(state.calls.get(plan.actions[0]!.actionId)).toBeUndefined();
      expect(state.roles.get("subject-1")).toBe("owner");
    } finally {
      store.close();
    }
  });

  it("audits a structurally invalid gateway payload before schema parsing", async () => {
    const { store } = await setup();
    try {
      const gateway = gatewayFor(store, mockState());
      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan: {} as never,
          action: {} as never,
        }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
      const audit = await store.execute({
        sql: `SELECT claimed_tenant_id, claimed_incident_id, claimed_plan_id,
          claimed_action_id, outcome, reason_code
          FROM containment_gateway_audit ORDER BY rowid DESC LIMIT 1`,
      });
      expect(audit.rows[0]).toEqual({
        claimed_tenant_id: "tenant-1",
        claimed_incident_id: "incident-1",
        claimed_plan_id: "invalid-plan",
        claimed_action_id: "invalid-action",
        outcome: "invalid",
        reason_code: "BINDING_INVALID",
      });
    } finally {
      store.close();
    }
  });

  it("recovers an after-effect provider failure by verification without a duplicate call", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.failAfterEffectActions = new Set([plan.actions[0]!.actionId]);
      const gateway = gatewayFor(store, state);
      const input = {
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: plan.actions[0]!,
      };
      await expect(gateway.executeApprovedAction(input)).resolves.toMatchObject(
        {
          status: "completed",
          verification: "verified",
        },
      );
      await expect(gateway.executeApprovedAction(input)).resolves.toMatchObject(
        {
          status: "completed",
          verification: "verified",
        },
      );
      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
    } finally {
      store.close();
    }
  });

  it("fences a timed-out mock call before it can apply a late effect", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.delayMs = 25;
      const gateway = new ContainmentGateway({
        store,
        state,
        mode: "mock",
        timeoutMs: 5,
        rateLimit: 8,
        clock: fixedClock("2026-08-27T12:03:00.000Z"),
      });
      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan,
          action: plan.actions[0]!,
        }),
      ).resolves.toMatchObject({
        status: "timed_out",
        errorCode: "PROVIDER_TIMEOUT",
      });
      await new Promise<void>((resolve) => setTimeout(resolve, 35));
      expect(state.roles.get("subject-1")).toBe("admin");
      expect(state.calls.get(plan.actions[0]!.actionId)).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("lets a second gateway reclaim an expired lease while fencing the old owner", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.delayMs = 50;
      let now = "2026-08-27T12:03:00.000Z";
      const clock: Clock = { now: () => now };
      const input = {
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: plan.actions[0]!,
      };
      const oldOwner = new ContainmentGateway({
        store,
        state,
        mode: "mock",
        timeoutMs: 20,
        rateLimit: 8,
        clock,
      }).executeApprovedAction(input);
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
      now = "2026-08-27T12:04:00.000Z";
      const successor = new ContainmentGateway({
        store,
        state,
        mode: "mock",
        timeoutMs: 200,
        rateLimit: 8,
        clock,
      }).executeApprovedAction(input);
      const results = await Promise.allSettled([oldOwner, successor]);
      expect(results[1]).toMatchObject({
        status: "fulfilled",
        value: { status: "completed", verification: "verified" },
      });
      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      const attempts = await store.execute({
        sql: `SELECT attempt, status FROM containment_action_attempts
          ORDER BY attempt`,
      });
      expect(attempts.rows).toEqual([
        { attempt: 1, status: "failed" },
        { attempt: 2, status: "completed" },
      ]);
    } finally {
      store.close();
    }
  });

  it("reconciles a post-effect crash after restart with a distinct mock state", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      let now = "2026-08-27T12:03:00.000Z";
      const clock: Clock = { now: () => now };
      const state = mockState();
      state.roles.set("subject-1", "admin");
      const crashAfterEffectStore: OperationalStore = {
        execute: (statement) => store.execute(statement),
        transaction: (operation) =>
          store.transaction((tx) =>
            operation({
              execute: async (statement) => {
                if (
                  statement.sql.includes(
                    "UPDATE containment_action_attempts SET status = ?, finished_at",
                  )
                ) {
                  throw new Error("process crashed before finish");
                }
                return tx.execute(statement);
              },
              batch: (statements) => tx.batch(statements),
            }),
          ),
        close: () => {},
      };
      const input = {
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: plan.actions[0]!,
      };
      await expect(
        new ContainmentGateway({
          store: crashAfterEffectStore,
          state,
          mode: "mock",
          timeoutMs: 1_000,
          rateLimit: 8,
          clock,
        }).executeApprovedAction(input),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      expect(state.roles.get("subject-1")).toBe("member");
      const crashed = await store.execute({
        sql: `SELECT status, verification FROM containment_action_attempts
          ORDER BY attempt`,
      });
      expect(crashed.rows).toEqual([
        { status: "executing", verification: "not_run" },
      ]);
      now = "2026-08-27T12:03:03.000Z";
      const restartedState = mockState();
      await expect(
        new ContainmentGateway({
          store,
          state: restartedState,
          mode: "mock",
          timeoutMs: 1_000,
          rateLimit: 8,
          clock,
        }).executeApprovedAction(input),
      ).resolves.toMatchObject({
        status: "completed",
        verification: "verified",
      });
      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      expect(
        restartedState.calls.get(plan.actions[0]!.actionId),
      ).toBeUndefined();
      const effect = await store.execute({
        sql: `SELECT attempt, action_type, target_id, provider_ref
          FROM mock_containment_effects`,
      });
      expect(effect.rows).toEqual([
        {
          attempt: 1,
          action_type: plan.actions[0]!.type,
          target_id: plan.actions[0]!.targetId,
          provider_ref: `mock-action-${plan.actions[0]!.actionId}`,
        },
      ]);
      await expect(
        store.execute({
          sql: `UPDATE mock_containment_effects SET provider_ref = 'tampered'
            WHERE action_id = ?`,
          args: [plan.actions[0]!.actionId],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      const recovered = await store.execute({
        sql: `SELECT attempt, status, verification FROM containment_action_attempts
          ORDER BY attempt`,
      });
      expect(recovered.rows).toEqual([
        { attempt: 1, status: "completed", verification: "verified" },
      ]);
    } finally {
      store.close();
    }
  });

  it("validates contained finalization before closing and replays without a closed-to-closed transition", async () => {
    const firstAction = makePlan().actions[0]!;
    const secondAction = {
      ...firstAction,
      actionId: "action-2",
      type: "revoke_session" as const,
      targetId: "session-1",
      input: {},
    };
    const plan = makePlan({ actions: [firstAction, secondAction] });
    const { database, store } = await setup(plan);
    try {
      const approved = await approve(store, plan);
      await transitionIncident(
        store,
        {
          tenantId: "tenant-1",
          incidentId: "incident-1",
          expectedVersion: 3,
          to: "containing",
          runId: "run-1",
          correlationId: "correlation-1",
        },
        {
          clock: fixedClock("2026-08-27T12:02:30.000Z"),
          ids: sequenceIdGenerator([
            "timeline-containing",
            "outbox-containing",
          ]),
        },
      );
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.sessions.set("session-1", "active");
      const gateway = gatewayFor(store, state);
      const firstOutcome = await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: firstAction,
      });
      const secondOutcome = await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: secondAction,
      });
      await recordContainmentOutcome(
        store,
        {
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          correlationId: "correlation-1",
          approvalId: "approval-1",
          expectedVersion: 4,
          status: "contained",
          partial: false,
          completedCount: 2,
          failedCount: 0,
        },
        {
          clock: fixedClock("2026-08-27T12:03:30.000Z"),
          ids: sequenceIdGenerator(["timeline-contained", "outbox-contained"]),
        },
      );
      const phase5 = await readPhase5Payload(store);
      const inputData = {
        status: "containment-succeeded" as const,
        decision: phase5.decision,
        summary: phase5.summary,
        plan,
        authoritative: {
          approvalId: approved.decision.approvalId,
          planId: approved.decision.planId,
          incidentId: approved.decision.incidentId,
          tenantId: approved.decision.tenantId,
          workflowRunId: "run-1",
          planHashVersion: approved.decision.planHashVersion,
          planHash: approved.decision.planHash,
          decision: approved.decision.decision,
          decidedBy: approved.decision.decidedBy,
          decidedByRole: approved.decision.decidedByRole,
          decidedAt: approved.decision.decidedAt,
          expiresAt: plan.expiresAt,
        },
        workflowRunId: "run-1",
        correlationId: "correlation-1",
        outcomes: [firstOutcome, secondOutcome],
      };
      const step = createFinalizeIncidentStep({
        openStore: () => database.createStore(),
        clock: fixedClock("2026-08-27T12:04:00.000Z"),
        ids: sequenceIdGenerator(["timeline-closed", "outbox-closed"]),
      });
      const execute = step.execute!;
      const eventsBeforeFirstValidation = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      const [racedPlan] = schemaValidPlanTamperings(plan).filter(
        (candidate) =>
          candidate.actions[0]?.targetId !== plan.actions[0]?.targetId,
      );
      let raceInjected = false;
      const raceStep = createFinalizeIncidentStep({
        openStore: () => {
          const delegate = database.createStore();
          return {
            execute: (statement) => delegate.execute(statement),
            transaction: async (operation) => {
              if (!raceInjected) {
                raceInjected = true;
                await store.execute({
                  sql: `UPDATE containment_plans SET plan_json = ?
                    WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
                      AND id = 'plan-1'`,
                  args: [JSON.stringify(racedPlan)],
                });
              }
              return delegate.transaction(operation);
            },
            close: () => delegate.close(),
          };
        },
        clock: fixedClock("2026-08-27T12:04:00.000Z"),
        ids: sequenceIdGenerator([
          "timeline-raced-closed",
          "outbox-raced-closed",
        ]),
      });
      await expect(
        raceStep.execute!({ inputData } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      expect(raceInjected).toBe(true);
      await store.execute({
        sql: `UPDATE containment_plans SET plan_json = ?
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND id = 'plan-1'`,
        args: [JSON.stringify(plan)],
      });
      for (const [field, value] of [
        ["approvalId", "different-approval"],
        ["tenantId", "different-tenant"],
        ["incidentId", "different-incident"],
        ["workflowRunId", "different-run"],
        ["planId", "different-plan"],
        ["planHash", "0".repeat(64)],
        ["decision", "rejected"],
        ["decidedBy", "different-manager"],
        ["decidedAt", "2026-08-27T12:02:01.000Z"],
        ["expiresAt", "2026-08-27T12:16:01.000Z"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          authoritative: { ...inputData.authoritative, [field]: value },
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const [field, value] of [
        ["workflowRunId", "different-run"],
        ["correlationId", "different-correlation"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          [field]: value,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const tamperedPlan of schemaValidPlanTamperings(plan)) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          plan: tamperedPlan,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      const firstDuplicateOutcome = ContainmentExecutionResultSchema.parse({
        ...inputData,
        outcomes: [firstOutcome, firstOutcome],
      });
      await expect(
        execute({ inputData: firstDuplicateOutcome } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      const firstInvertedOutcomes = ContainmentExecutionResultSchema.parse({
        ...inputData,
        outcomes: [secondOutcome, firstOutcome],
      });
      await expect(
        execute({ inputData: firstInvertedOutcomes } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      const stateAfterFirstDivergences = await store.execute({
        sql: `SELECT status, closed_at FROM incidents
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      const eventsAfterFirstDivergences = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(stateAfterFirstDivergences.rows[0]).toEqual({
        status: "contained",
        closed_at: null,
      });
      expect(eventsAfterFirstDivergences.rows[0]?.count).toBe(
        eventsBeforeFirstValidation.rows[0]?.count,
      );
      const first = await execute({ inputData } as never);
      const eventsAfterFirst = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      const replay = await execute({ inputData } as never);
      const eventsAfterReplay = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(replay).toEqual(first);
      expect(replay).toMatchObject({ status: "contained" });
      expect(eventsAfterReplay.rows[0]?.count).toBe(
        eventsAfterFirst.rows[0]?.count,
      );
      for (const [field, value] of [
        ["approvalId", "different-approval"],
        ["tenantId", "different-tenant"],
        ["incidentId", "different-incident"],
        ["workflowRunId", "different-run"],
        ["planId", "different-plan"],
        ["planHash", "0".repeat(64)],
        ["decision", "rejected"],
        ["decidedBy", "different-manager"],
        ["decidedAt", "2026-08-27T12:02:01.000Z"],
        ["expiresAt", "2026-08-27T12:16:01.000Z"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          authoritative: { ...inputData.authoritative, [field]: value },
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const [field, value] of [
        ["workflowRunId", "different-run"],
        ["correlationId", "different-correlation"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          [field]: value,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const tamperedPlan of schemaValidPlanTamperings(plan)) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          plan: tamperedPlan,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      const duplicateOutcome = ContainmentExecutionResultSchema.parse({
        ...inputData,
        outcomes: [firstOutcome, firstOutcome],
      });
      await expect(
        execute({ inputData: duplicateOutcome } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      const invertedOutcomes = ContainmentExecutionResultSchema.parse({
        ...inputData,
        outcomes: [secondOutcome, firstOutcome],
      });
      await expect(
        execute({ inputData: invertedOutcomes } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      await store.execute({
        sql: `UPDATE incidents SET closed_at = '2026-08-27T12:04:01.000Z'
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      await expect(execute({ inputData } as never)).rejects.toMatchObject({
        code: "CONFLICT",
      });
      const eventsAfterDivergence = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(eventsAfterDivergence.rows[0]?.count).toBe(
        eventsAfterReplay.rows[0]?.count,
      );
    } finally {
      store.close();
    }
  });

  it("validates rejected finalization before closing and replays the same terminal result", async () => {
    const { database, store, plan } = await setup();
    try {
      const rejected = await reject(store, plan);
      const phase5 = await readPhase5Payload(store);
      const inputData = {
        status: "rejected" as const,
        decision: phase5.decision,
        summary: phase5.summary,
        plan,
        authoritative: {
          approvalId: rejected.decision.approvalId,
          planId: rejected.decision.planId,
          incidentId: rejected.decision.incidentId,
          tenantId: rejected.decision.tenantId,
          workflowRunId: "run-1",
          planHashVersion: rejected.decision.planHashVersion,
          planHash: rejected.decision.planHash,
          decision: rejected.decision.decision,
          decidedBy: rejected.decision.decidedBy,
          decidedByRole: rejected.decision.decidedByRole,
          decidedAt: rejected.decision.decidedAt,
          expiresAt: plan.expiresAt,
        },
        workflowRunId: "run-1",
        correlationId: "correlation-1",
      };
      const step = createFinalizeIncidentStep({
        openStore: () => database.createStore(),
        clock: fixedClock("2026-08-27T12:04:00.000Z"),
        ids: sequenceIdGenerator(["timeline-closed", "outbox-closed"]),
      });
      const execute = step.execute!;
      const eventsBeforeFirstValidation = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      const [qaTamperedPlan] = schemaValidPlanTamperings(plan).filter(
        (candidate) =>
          candidate.actions[0]?.targetId !== plan.actions[0]?.targetId,
      );
      const qaRejectedDivergence = ContainmentExecutionResultSchema.parse({
        ...inputData,
        plan: qaTamperedPlan,
        authoritative: {
          ...inputData.authoritative,
          approvalId: "forged-approval",
        },
      });
      await expect(
        execute({ inputData: qaRejectedDivergence } as never),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      for (const [field, value] of [
        ["workflowRunId", "different-run"],
        ["correlationId", "different-correlation"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          [field]: value,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const [field, value] of [
        ["approvalId", "different-approval"],
        ["tenantId", "different-tenant"],
        ["incidentId", "different-incident"],
        ["workflowRunId", "different-run"],
        ["planId", "different-plan"],
        ["planHash", "0".repeat(64)],
        ["decision", "approved"],
        ["decidedBy", "different-manager"],
        ["decidedAt", "2026-08-27T12:02:01.000Z"],
        ["expiresAt", "2026-08-27T12:16:01.000Z"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          authoritative: { ...inputData.authoritative, [field]: value },
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const tamperedPlan of schemaValidPlanTamperings(plan)) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          plan: tamperedPlan,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      const stateAfterFirstDivergences = await store.execute({
        sql: `SELECT status, closed_at FROM incidents
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      const eventsAfterFirstDivergences = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(stateAfterFirstDivergences.rows[0]).toEqual({
        status: "rejected",
        closed_at: null,
      });
      expect(eventsAfterFirstDivergences.rows[0]?.count).toBe(
        eventsBeforeFirstValidation.rows[0]?.count,
      );
      const first = await execute({ inputData } as never);
      const eventsAfterFirst = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      const replay = await execute({ inputData } as never);
      const eventsAfterReplay = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(replay).toEqual(first);
      expect(replay).toEqual({
        status: "rejected",
        incidentId: "incident-1",
        approvalId: "approval-1",
      });
      expect(eventsAfterReplay.rows[0]?.count).toBe(
        eventsAfterFirst.rows[0]?.count,
      );
      for (const [field, value] of [
        ["workflowRunId", "different-run"],
        ["correlationId", "different-correlation"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          [field]: value,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const [field, value] of [
        ["approvalId", "different-approval"],
        ["tenantId", "different-tenant"],
        ["incidentId", "different-incident"],
        ["workflowRunId", "different-run"],
        ["planId", "different-plan"],
        ["planHash", "0".repeat(64)],
        ["decision", "approved"],
        ["decidedBy", "different-manager"],
        ["decidedAt", "2026-08-27T12:02:01.000Z"],
        ["expiresAt", "2026-08-27T12:16:01.000Z"],
      ] as const) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          authoritative: { ...inputData.authoritative, [field]: value },
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      for (const tamperedPlan of schemaValidPlanTamperings(plan)) {
        const divergent = ContainmentExecutionResultSchema.parse({
          ...inputData,
          plan: tamperedPlan,
        });
        await expect(
          execute({ inputData: divergent } as never),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      }
      await store.execute({
        sql: `UPDATE incidents SET closed_at = '2026-08-27T12:04:01.000Z'
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      await expect(execute({ inputData } as never)).rejects.toMatchObject({
        code: "CONFLICT",
      });
      const eventsAfterDivergence = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE type = 'incident.status_changed'`,
      });
      expect(eventsAfterDivergence.rows[0]?.count).toBe(
        eventsAfterReplay.rows[0]?.count,
      );
    } finally {
      store.close();
    }
  });

  it("stops on the first failure and retries only failed/pending actions", async () => {
    const first = makePlan().actions[0]!;
    const second = {
      ...first,
      actionId: "action-2",
      type: "revoke_session" as const,
      targetId: "session-1",
      input: {},
    };
    const plan = makePlan({ actions: [first, second] });
    const { store } = await setup(plan);
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.sessions.set("session-1", "active");
      state.failActions = new Set([second.actionId]);
      const gateway = gatewayFor(store, state);
      expect(
        (
          await gateway.executeApprovedAction({
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
            plan,
            action: first,
          })
        ).status,
      ).toBe("completed");
      expect(
        (
          await gateway.executeApprovedAction({
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
            plan,
            action: second,
          })
        ).status,
      ).toBe("failed");
      state.failActions.clear();
      await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: first,
      });
      await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: second,
      });
      expect(state.calls.get(first.actionId)).toBe(1);
      expect(state.calls.get(second.actionId)).toBe(2);
      expect(state.roles.get("subject-1")).toBe("member");
      expect(state.sessions.get("session-1")).toBe("revoked");
    } finally {
      store.close();
    }
  });

  it("enforces plan order in the gateway and audits the blocked successor", async () => {
    const first = makePlan().actions[0]!;
    const second = {
      ...first,
      actionId: "action-2",
      type: "revoke_session" as const,
      targetId: "session-1",
      input: {},
    };
    const plan = makePlan({ actions: [first, second] });
    const { store } = await setup(plan);
    try {
      await approve(store, plan);
      const state = mockState();
      state.sessions.set("session-1", "active");
      await expect(
        gatewayFor(store, state).executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan,
          action: second,
        }),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      expect(state.calls.size).toBe(0);
      const audit = await store.execute({
        sql: `SELECT outcome, reason_code FROM containment_gateway_audit
          ORDER BY occurred_at DESC LIMIT 1`,
      });
      expect(audit.rows[0]).toEqual({
        outcome: "blocked",
        reason_code: "PREDECESSOR_INCOMPLETE",
      });
    } finally {
      store.close();
    }
  });

  it("caps failed action retries before a fourth effect can run", async () => {
    const plan = makePlan();
    const action = plan.actions[0]!;
    const { store } = await setup(plan);
    try {
      await approve(store, plan);
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.failActions = new Set([action.actionId]);
      const gateway = gatewayFor(store, state);
      const input = {
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action,
      } as const;

      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expect(
          gateway.executeApprovedAction(input),
        ).resolves.toMatchObject({
          status: "failed",
        });
      }
      await expect(gateway.executeApprovedAction(input)).rejects.toMatchObject({
        code: "CONFLICT",
      });

      expect(state.calls.get(action.actionId)).toBe(3);
      const attempts = await store.execute({
        sql: `SELECT count(*) AS count FROM containment_action_attempts
          WHERE action_id = ?`,
        args: [action.actionId],
      });
      expect(Number(attempts.rows[0]?.count)).toBe(3);
      const audit = await store.execute({
        sql: `SELECT outcome, reason_code FROM containment_gateway_audit
          ORDER BY rowid DESC LIMIT 1`,
      });
      expect(audit.rows[0]).toEqual({
        outcome: "rate_limited",
        reason_code: "RATE_LIMITED",
      });
    } finally {
      store.close();
    }
  });

  it("shares the tenant rate-limit budget across incidents for the same action type", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const second = await setupAdditionalApprovedIncident(
        store,
        "restore_previous_role",
      );
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.roles.set("subject-2", "admin");
      const gateway = new ContainmentGateway({
        store,
        state,
        mode: "mock",
        timeoutMs: 1_000,
        rateLimit: 1,
        clock: fixedClock("2026-08-27T12:03:00.000Z"),
      });

      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan,
          action: plan.actions[0]!,
        }),
      ).resolves.toMatchObject({ status: "completed" });
      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-2",
          workflowRunId: "run-2",
          approvalId: "approval-2",
          plan: second.plan,
          action: second.action,
        }),
      ).rejects.toMatchObject({ code: "CONFLICT" });

      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      expect(state.calls.get(second.action.actionId)).toBeUndefined();
      const audit = await store.execute({
        sql: `SELECT claimed_action_id, outcome, reason_code
          FROM containment_gateway_audit ORDER BY rowid DESC LIMIT 1`,
      });
      expect(audit.rows[0]).toEqual({
        claimed_action_id: second.action.actionId,
        outcome: "rate_limited",
        reason_code: "RATE_LIMITED",
      });
    } finally {
      store.close();
    }
  });

  it("keeps independent tenant rate-limit budgets for distinct action types", async () => {
    const { store, plan } = await setup();
    try {
      await approve(store, plan);
      const second = await setupAdditionalApprovedIncident(
        store,
        "revoke_session",
      );
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.sessions.set("session-2", "active");
      const gateway = new ContainmentGateway({
        store,
        state,
        mode: "mock",
        timeoutMs: 1_000,
        rateLimit: 1,
        clock: fixedClock("2026-08-27T12:03:00.000Z"),
      });

      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          approvalId: "approval-1",
          plan,
          action: plan.actions[0]!,
        }),
      ).resolves.toMatchObject({ status: "completed" });
      await expect(
        gateway.executeApprovedAction({
          tenantId: "tenant-1",
          incidentId: "incident-2",
          workflowRunId: "run-2",
          approvalId: "approval-2",
          plan: second.plan,
          action: second.action,
        }),
      ).resolves.toMatchObject({ status: "completed" });

      expect(state.calls.get(plan.actions[0]!.actionId)).toBe(1);
      expect(state.calls.get(second.action.actionId)).toBe(1);
    } finally {
      store.close();
    }
  });

  it("recovers an aggregate failed incident without repeating verified actions", async () => {
    const first = makePlan().actions[0]!;
    const second = {
      ...first,
      actionId: "action-2",
      type: "revoke_session" as const,
      targetId: "session-1",
      input: {},
    };
    const plan = makePlan({ actions: [first, second] });
    const { store } = await setup(plan);
    try {
      await approve(store, plan);
      await transitionIncident(
        store,
        {
          tenantId: "tenant-1",
          incidentId: "incident-1",
          expectedVersion: 3,
          to: "containing",
          runId: "run-1",
          correlationId: "correlation-1",
          causationId: "approval-1",
        },
        {
          clock: fixedClock("2026-08-27T12:03:00.000Z"),
          ids: sequenceIdGenerator([
            "containing-timeline",
            "containing-outbox",
          ]),
        },
      );
      const state = mockState();
      state.roles.set("subject-1", "admin");
      state.sessions.set("session-1", "active");
      state.failActions = new Set([second.actionId]);
      const gateway = gatewayFor(store, state);
      await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: first,
      });
      await gateway.executeApprovedAction({
        tenantId: "tenant-1",
        incidentId: "incident-1",
        workflowRunId: "run-1",
        approvalId: "approval-1",
        plan,
        action: second,
      });
      await recordContainmentOutcome(
        store,
        {
          tenantId: "tenant-1",
          incidentId: "incident-1",
          workflowRunId: "run-1",
          correlationId: "correlation-1",
          approvalId: "approval-1",
          expectedVersion: 4,
          status: "failed",
          partial: true,
          completedCount: 1,
          failedCount: 1,
        },
        {
          clock: fixedClock("2026-08-27T12:03:00.000Z"),
          ids: sequenceIdGenerator(["failed-timeline", "failed-outbox"]),
        },
      );
      state.failActions.clear();
      await expect(
        retryPartialContainment(
          store,
          {
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
            correlationId: "retry-correlation-1",
            state,
            mode: "mock",
            timeoutMs: 1_000,
            rateLimit: 8,
          },
          { clock: fixedClock("2026-08-27T12:04:00.000Z") },
        ),
      ).resolves.toMatchObject({ status: "contained" });
      expect(state.calls.get(first.actionId)).toBe(1);
      expect(state.calls.get(second.actionId)).toBe(2);
      const final = await store.execute({
        sql: "SELECT status FROM incidents WHERE id = 'incident-1'",
      });
      expect(final.rows[0]?.status).toBe("closed");
    } finally {
      store.close();
    }
  });

  it("rechecks partial-recovery terminal readiness inside the close transaction", async () => {
    const first = makePlan().actions[0]!;
    const second = {
      ...first,
      actionId: "action-2",
      type: "revoke_session" as const,
      targetId: "session-1",
      input: {},
    };
    const plan = makePlan({ actions: [first, second] });
    const { store } = await setup(plan);
    try {
      const prepared = await preparePartialContainmentFailure(store, plan);
      let terminalReadbackSeen = false;
      let raceInjected = false;
      const tamperedPlan = {
        ...plan,
        actions: [{ ...first, targetId: "tampered-subject" }, second],
      };
      const racingStore: OperationalStore = {
        execute: async (statement) => {
          const result = await store.execute(statement);
          if (statement.sql.includes("incident.status AS incident_status")) {
            terminalReadbackSeen = true;
          }
          return result;
        },
        transaction: async (operation) => {
          if (terminalReadbackSeen && !raceInjected) {
            raceInjected = true;
            await store.execute({
              sql: `UPDATE containment_plans SET plan_json = ?
                WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
                  AND id = ?`,
              args: [JSON.stringify(tamperedPlan), plan.planId],
            });
          }
          return store.transaction(operation);
        },
        close: () => undefined,
      };

      await expect(
        retryPartialContainment(
          racingStore,
          {
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
            correlationId: "retry-correlation-1",
            state: prepared.state,
            mode: "mock",
            timeoutMs: 1_000,
            rateLimit: 8,
          },
          { clock: fixedClock("2026-08-27T12:04:00.000Z") },
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });

      expect(raceInjected).toBe(true);
      const interrupted = await store.execute({
        sql: `SELECT status, closed_at FROM incidents
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      expect(interrupted.rows[0]).toEqual({
        status: "contained",
        closed_at: null,
      });
      const terminalEvents = await store.execute({
        sql: `SELECT count(*) AS count FROM timeline_events
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND type = 'incident.status_changed'
            AND json_extract(payload_json, '$.to') = 'closed'`,
      });
      expect(Number(terminalEvents.rows[0]?.count)).toBe(0);
      expect(prepared.state.calls.get(first.actionId)).toBe(1);
      expect(prepared.state.calls.get(second.actionId)).toBe(2);

      await store.execute({
        sql: `UPDATE containment_plans SET plan_json = ?
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND id = ?`,
        args: [JSON.stringify(plan), plan.planId],
      });
      const retryContained = (correlationId = "retry-correlation-1") =>
        retryPartialContainment(
          store,
          {
            tenantId: "tenant-1",
            incidentId: "incident-1",
            workflowRunId: "run-1",
            approvalId: "approval-1",
            correlationId,
            state: prepared.state,
            mode: "mock",
            timeoutMs: 1_000,
            rateLimit: 8,
          },
          { clock: fixedClock("2026-08-27T12:04:01.000Z") },
        );
      await store.execute({
        sql: `UPDATE approvals SET decided_by = 'tampered-manager'
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND id = 'approval-1'`,
      });
      await expect(retryContained()).rejects.toMatchObject({
        code: "CONFLICT",
      });
      await store.execute({
        sql: `UPDATE approvals SET decided_by = 'studio-soc-manager'
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND id = 'approval-1'`,
      });
      await store.execute({
        sql: `UPDATE containment_actions SET ordinal = 1 - ordinal
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND plan_id = ?`,
        args: [plan.planId],
      });
      await expect(retryContained()).rejects.toMatchObject({
        code: "CONFLICT",
      });
      await store.execute({
        sql: `UPDATE containment_actions
          SET ordinal = CASE action_id WHEN ? THEN 0 ELSE 1 END
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
            AND plan_id = ?`,
        args: [first.actionId, plan.planId],
      });
      await expect(
        retryContained("different-correlation"),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      const stillInterrupted = await store.execute({
        sql: `SELECT status, closed_at FROM incidents
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      expect(stillInterrupted.rows[0]).toEqual({
        status: "contained",
        closed_at: null,
      });
      const dispatcher = new Phase6RecoveryDispatcher({
        store,
        provider: new MockIncidentProvider(),
        reconcileApprovalRun: async () => "completed",
        containmentState: prepared.state,
        mode: "mock",
        actionTimeoutMs: 1_000,
        rateLimit: 8,
        clock: fixedClock("2026-08-27T12:04:01.000Z"),
      });
      await expect(dispatcher.runOnce()).resolves.toMatchObject({
        containmentRetried: 1,
      });
      const recovered = await store.execute({
        sql: `SELECT status, closed_at FROM incidents
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      expect(recovered.rows[0]).toEqual({
        status: "closed",
        closed_at: "2026-08-27T12:04:01.000Z",
      });
      expect(prepared.state.calls.get(first.actionId)).toBe(1);
      expect(prepared.state.calls.get(second.actionId)).toBe(2);
    } finally {
      store.close();
    }
  });

  it("audits a transient external failure and converges by the same delivery key", async () => {
    const { store, plan } = await setup();
    try {
      const provider = new MockIncidentProvider({ failAttempts: 1 });
      let now = "2026-08-27T12:02:00.000Z";
      const clock: Clock = { now: () => now };
      const projection = ExternalIncidentProjectionSchema.parse({
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change",
        severity: "high",
        status: "awaiting_approval",
        occurredAt: "2026-08-27T12:00:00.000Z",
        summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
        planHashVersion: 1,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "open-awaiting-approval",
            projection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock, ids: sequenceIdGenerator(["provider-timeline-1"]) },
        ),
      ).resolves.toMatchObject({ status: "retry_scheduled" });
      now = "2026-08-27T12:02:01.000Z";
      const dispatcher = new Phase6RecoveryDispatcher({
        store,
        provider,
        reconcileApprovalRun: async () => "completed",
        clock,
        ids: sequenceIdGenerator(["provider-timeline-2"]),
      });
      await expect(dispatcher.runOnce()).resolves.toMatchObject({
        delivered: 1,
      });
      const delivery = await store.execute({
        sql: "SELECT status, attempt_count, external_ref FROM provider_deliveries",
      });
      expect(delivery.rows[0]).toMatchObject({
        status: "succeeded",
        attempt_count: 2,
      });
      expect(provider.calls).toHaveLength(2);
    } finally {
      store.close();
    }
  });

  it("terminates a final delivery when its external create dependency is exhausted", async () => {
    const { store, plan } = await setup();
    try {
      const provider = new MockIncidentProvider({ failAttempts: 1 });
      const clock = fixedClock("2026-08-27T12:02:00.000Z");
      const base = {
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change" as const,
        severity: "high" as const,
        occurredAt: "2026-08-27T12:00:00.000Z",
        planHashVersion: 1 as const,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      };
      const finalProjection = ExternalIncidentProjectionSchema.parse({
        ...base,
        status: "failed",
        summaryCode: "CONTAINMENT_FAILED",
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-failed",
            projection: finalProjection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock },
        ),
      ).resolves.toMatchObject({ status: "in_progress", attemptCount: 0 });
      const waitingDispatcher = new Phase6RecoveryDispatcher({
        store,
        provider,
        clock,
        reconcileApprovalRun: async () => "completed",
      });
      await expect(waitingDispatcher.runOnce()).resolves.toMatchObject({
        delivered: 0,
      });
      const openProjection = ExternalIncidentProjectionSchema.parse({
        ...base,
        status: "awaiting_approval",
        summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "open-awaiting-approval",
            projection: openProjection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          {
            clock,
            ids: sequenceIdGenerator(["open-exhausted-audit"]),
            maxAttempts: 1,
          },
        ),
      ).resolves.toMatchObject({ status: "exhausted" });
      const dispatcher = new Phase6RecoveryDispatcher({
        store,
        provider,
        clock,
        reconcileApprovalRun: async () => "completed",
        ids: sequenceIdGenerator(["dependency-exhausted-audit"]),
      });
      await expect(dispatcher.runOnce()).resolves.toMatchObject({
        delivered: 1,
      });
      await expect(dispatcher.runOnce()).resolves.toMatchObject({
        delivered: 0,
      });
      const deliveries = await store.execute({
        sql: `SELECT operation, status, attempt_count, error_code
          FROM provider_deliveries ORDER BY operation`,
      });
      expect(deliveries.rows).toEqual([
        {
          operation: "final-failed",
          status: "exhausted",
          attempt_count: 0,
          error_code: "PROVIDER_DEPENDENCY_EXHAUSTED",
        },
        {
          operation: "open-awaiting-approval",
          status: "exhausted",
          attempt_count: 1,
          error_code: "PROVIDER_UNAVAILABLE",
        },
      ]);
    } finally {
      store.close();
    }
  });

  it("supersedes a stale final-failed retry after partial recovery closes the incident", async () => {
    const { store, plan } = await setup();
    try {
      let now = "2026-08-27T12:02:00.000Z";
      const clock: Clock = { now: () => now };
      let externalStatus = "none";
      let failOldFinal = true;
      const calls: string[] = [];
      const provider: IncidentProvider = {
        create: async ({ projection }) => {
          calls.push("open");
          externalStatus = projection.status;
          return { externalRef: "mock-incident-0000000000000001" };
        },
        update: async ({ projection }) => {
          if (projection.summaryCode === "CONTAINMENT_FAILED" && failOldFinal) {
            failOldFinal = false;
            calls.push("final-failed-error");
            throw new Error("transient final failure");
          }
          calls.push(projection.summaryCode);
          externalStatus = projection.status;
          return { externalRef: "mock-incident-0000000000000001" };
        },
      };
      const base = {
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change" as const,
        severity: "high" as const,
        occurredAt: "2026-08-27T12:00:00.000Z",
        planHashVersion: 1 as const,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      };
      await deliverExternalIncident(
        store,
        provider,
        {
          operation: "open-awaiting-approval",
          projection: ExternalIncidentProjectionSchema.parse({
            ...base,
            status: "awaiting_approval",
            summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
          }),
          workflowRunId: "run-1",
          correlationId: "correlation-1",
        },
        { clock, ids: sequenceIdGenerator(["open-audit"]) },
      );
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-failed",
            projection: ExternalIncidentProjectionSchema.parse({
              ...base,
              status: "failed",
              summaryCode: "CONTAINMENT_FAILED",
            }),
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock, ids: sequenceIdGenerator(["failed-retry-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "retry_scheduled" });
      await store.execute({
        sql: `UPDATE incidents SET status = 'closed', updated_at = ?
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
        args: [now],
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-contained",
            projection: ExternalIncidentProjectionSchema.parse({
              ...base,
              status: "closed",
              summaryCode: "CONTAINMENT_SUCCEEDED",
            }),
            workflowRunId: "run-1",
            correlationId: "partial-retry-1",
          },
          { clock, ids: sequenceIdGenerator(["contained-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "succeeded" });
      expect(externalStatus).toBe("closed");
      now = "2026-08-27T12:02:01.000Z";
      const dispatcher = new Phase6RecoveryDispatcher({
        store,
        provider,
        clock,
        reconcileApprovalRun: async () => "completed",
        ids: sequenceIdGenerator(["superseded-audit"]),
      });
      await expect(dispatcher.runOnce()).resolves.toMatchObject({
        delivered: 1,
      });
      expect(externalStatus).toBe("closed");
      expect(calls).toEqual([
        "open",
        "final-failed-error",
        "CONTAINMENT_SUCCEEDED",
      ]);
      const stale = await store.execute({
        sql: `SELECT status, error_code FROM provider_deliveries
          WHERE operation = 'final-failed'`,
      });
      expect(stale.rows[0]).toEqual({
        status: "exhausted",
        error_code: "PROVIDER_DELIVERY_SUPERSEDED",
      });
      const incident = await store.execute({
        sql: "SELECT status FROM incidents WHERE id = 'incident-1'",
      });
      expect(incident.rows[0]?.status).toBe("closed");
    } finally {
      store.close();
    }
  });

  it("rechecks final-failed supersession after claim and before the provider update", async () => {
    const { store, plan } = await setup();
    try {
      let now = "2026-08-27T12:02:00.000Z";
      const clock: Clock = { now: () => now };
      let externalStatus = "none";
      let finalFailedCalls = 0;
      const provider: IncidentProvider = {
        create: async ({ projection }) => {
          externalStatus = projection.status;
          return { externalRef: "mock-incident-0000000000000001" };
        },
        update: async ({ projection }) => {
          if (projection.summaryCode === "CONTAINMENT_FAILED") {
            finalFailedCalls += 1;
            if (finalFailedCalls === 1) throw new Error("transient failure");
          }
          externalStatus = projection.status;
          return { externalRef: "mock-incident-0000000000000001" };
        },
      };
      const base = {
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change" as const,
        severity: "high" as const,
        occurredAt: "2026-08-27T12:00:00.000Z",
        planHashVersion: 1 as const,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      };
      await deliverExternalIncident(
        store,
        provider,
        {
          operation: "open-awaiting-approval",
          projection: ExternalIncidentProjectionSchema.parse({
            ...base,
            status: "awaiting_approval",
            summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
          }),
          workflowRunId: "run-1",
          correlationId: "correlation-1",
        },
        { clock, ids: sequenceIdGenerator(["open-audit"]) },
      );
      const failedProjection = ExternalIncidentProjectionSchema.parse({
        ...base,
        status: "failed",
        summaryCode: "CONTAINMENT_FAILED",
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-failed",
            projection: failedProjection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock, ids: sequenceIdGenerator(["failed-retry-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "retry_scheduled" });
      now = "2026-08-27T12:02:01.000Z";
      let recoveryInterleaved = false;
      const interleavingStore: OperationalStore = {
        transaction: (operation) => store.transaction(operation),
        execute: async (statement) => {
          if (
            !recoveryInterleaved &&
            statement.sql.includes("SELECT status FROM incidents")
          ) {
            recoveryInterleaved = true;
            await store.execute({
              sql: `UPDATE incidents SET status = 'closed', updated_at = ?
                WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
              args: [now],
            });
            externalStatus = "closed";
          }
          return store.execute(statement);
        },
        close: () => undefined,
      };
      await expect(
        deliverExternalIncident(
          interleavingStore,
          provider,
          {
            operation: "final-failed",
            projection: failedProjection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock, ids: sequenceIdGenerator(["superseded-after-claim-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "exhausted", attemptCount: 2 });
      expect(recoveryInterleaved).toBe(true);
      expect(finalFailedCalls).toBe(1);
      expect(externalStatus).toBe("closed");
      const delivery = await store.execute({
        sql: `SELECT status, error_code FROM provider_deliveries
          WHERE operation = 'final-failed'`,
      });
      expect(delivery.rows[0]).toEqual({
        status: "exhausted",
        error_code: "PROVIDER_DELIVERY_SUPERSEDED",
      });
    } finally {
      store.close();
    }
  });

  it("rejects a stale final-failed generation inside the provider after a concurrent recovery", async () => {
    const { store, plan } = await setup();
    try {
      let now = "2026-08-27T12:02:00.000Z";
      const clock: Clock = { now: () => now };
      let finalFailedAttempt = 0;
      let enterStaleUpdate!: () => void;
      let releaseStaleUpdate!: () => void;
      const staleUpdateEntered = new Promise<void>((resolve) => {
        enterStaleUpdate = resolve;
      });
      const staleUpdateRelease = new Promise<void>((resolve) => {
        releaseStaleUpdate = resolve;
      });
      const provider = new MockIncidentProvider({
        store,
        beforePersist: async ({ projection }) => {
          if (projection.summaryCode !== "CONTAINMENT_FAILED") return;
          finalFailedAttempt += 1;
          if (finalFailedAttempt === 1) throw new Error("transient failure");
          enterStaleUpdate();
          await staleUpdateRelease;
        },
      });
      const base = {
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change" as const,
        severity: "high" as const,
        occurredAt: "2026-08-27T12:00:00.000Z",
        planHashVersion: 1 as const,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      };
      await deliverExternalIncident(
        store,
        provider,
        {
          operation: "open-awaiting-approval",
          projection: ExternalIncidentProjectionSchema.parse({
            ...base,
            status: "awaiting_approval",
            summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
          }),
          workflowRunId: "run-1",
          correlationId: "correlation-1",
        },
        { clock, ids: sequenceIdGenerator(["open-audit"]) },
      );
      await store.execute({
        sql: `UPDATE incidents SET status = 'failed', version = version + 1,
          updated_at = ? WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
        args: [now],
      });
      const failedProjection = ExternalIncidentProjectionSchema.parse({
        ...base,
        status: "failed",
        summaryCode: "CONTAINMENT_FAILED",
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-failed",
            projection: failedProjection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          { clock, ids: sequenceIdGenerator(["failed-retry-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "retry_scheduled" });
      now = "2026-08-27T12:02:01.000Z";
      const stale = deliverExternalIncident(
        store,
        provider,
        {
          operation: "final-failed",
          projection: failedProjection,
          workflowRunId: "run-1",
          correlationId: "correlation-1",
        },
        { clock, ids: sequenceIdGenerator(["superseded-audit"]) },
      );
      await staleUpdateEntered;
      await store.execute({
        sql: `UPDATE incidents SET status = 'closed', version = version + 1,
          updated_at = ? WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
        args: [now],
      });
      await expect(
        deliverExternalIncident(
          store,
          provider,
          {
            operation: "final-contained",
            projection: ExternalIncidentProjectionSchema.parse({
              ...base,
              status: "closed",
              summaryCode: "CONTAINMENT_SUCCEEDED",
            }),
            workflowRunId: "run-1",
            correlationId: "partial-retry-1",
          },
          { clock, ids: sequenceIdGenerator(["contained-audit"]) },
        ),
      ).resolves.toMatchObject({ status: "succeeded" });
      releaseStaleUpdate();
      await expect(stale).resolves.toMatchObject({
        status: "exhausted",
        attemptCount: 2,
      });
      const external = await store.execute({
        sql: `SELECT generation, projection_json
          FROM mock_incident_provider_effects
          WHERE tenant_id = 'tenant-1' AND incident_id = 'incident-1'
          ORDER BY generation DESC LIMIT 1`,
      });
      expect(external.rows[0]?.generation).toBe(4);
      expect(
        JSON.parse(String(external.rows[0]?.projection_json)),
      ).toMatchObject({
        status: "closed",
        summaryCode: "CONTAINMENT_SUCCEEDED",
      });
      const staleDelivery = await store.execute({
        sql: `SELECT status, error_code FROM provider_deliveries
          WHERE operation = 'final-failed'`,
      });
      expect(staleDelivery.rows[0]).toEqual({
        status: "exhausted",
        error_code: "PROVIDER_DELIVERY_SUPERSEDED",
      });
    } finally {
      store.close();
    }
  });

  it.each([
    ["empty", { externalRef: "" }],
    ["invalid-format", { externalRef: "external-ticket-1" }],
    [
      "extra-field",
      { externalRef: "mock-incident-0000000000000001", secret: "must-drop" },
    ],
  ])(
    "fails closed for a %s provider result and terminalizes its dependent update",
    async (_case, malformed) => {
      const { store, plan } = await setup();
      try {
        let providerCalls = 0;
        const provider: IncidentProvider = {
          create: async () => {
            providerCalls += 1;
            return malformed as never;
          },
          update: async () => {
            providerCalls += 1;
            return malformed as never;
          },
        };
        const base = {
          incidentId: "incident-1",
          tenantId: "tenant-1",
          kind: "unauthorized_privilege_change" as const,
          severity: "high" as const,
          occurredAt: "2026-08-27T12:00:00.000Z",
          planHashVersion: 1 as const,
          planHash: plan.planHash,
          actionTypes: plan.actions.map((action) => action.type),
        };
        await expect(
          deliverExternalIncident(
            store,
            provider,
            {
              operation: "open-awaiting-approval",
              projection: ExternalIncidentProjectionSchema.parse({
                ...base,
                status: "awaiting_approval",
                summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
              }),
              workflowRunId: "run-1",
              correlationId: "correlation-1",
            },
            {
              clock: fixedClock("2026-08-27T12:02:00.000Z"),
              ids: sequenceIdGenerator(["malformed-open-audit"]),
              maxAttempts: 1,
            },
          ),
        ).resolves.toMatchObject({ status: "exhausted" });
        await expect(
          deliverExternalIncident(
            store,
            provider,
            {
              operation: "final-failed",
              projection: ExternalIncidentProjectionSchema.parse({
                ...base,
                status: "failed",
                summaryCode: "CONTAINMENT_FAILED",
              }),
              workflowRunId: "run-1",
              correlationId: "correlation-1",
            },
            {
              clock: fixedClock("2026-08-27T12:02:01.000Z"),
              ids: sequenceIdGenerator(["malformed-dependent-audit"]),
              maxAttempts: 1,
            },
          ),
        ).resolves.toMatchObject({ status: "exhausted" });
        const deliveries = await store.execute({
          sql: `SELECT operation, status, external_ref, error_code
            FROM provider_deliveries ORDER BY operation`,
        });
        expect(deliveries.rows).toEqual([
          {
            operation: "final-failed",
            status: "exhausted",
            external_ref: null,
            error_code: "PROVIDER_DEPENDENCY_EXHAUSTED",
          },
          {
            operation: "open-awaiting-approval",
            status: "exhausted",
            external_ref: null,
            error_code: "PROVIDER_UNAVAILABLE",
          },
        ]);
        expect(JSON.stringify(deliveries.rows)).not.toContain("must-drop");
        expect(providerCalls).toBe(1);
      } finally {
        store.close();
      }
    },
  );

  it("atomically reconciles provider success with its delivery audit", async () => {
    const { store, plan } = await setup();
    try {
      let now = "2026-08-27T12:02:00.000Z";
      const clock: Clock = { now: () => now };
      const providerBeforeRestart = new MockIncidentProvider({ store });
      const projection = ExternalIncidentProjectionSchema.parse({
        incidentId: "incident-1",
        tenantId: "tenant-1",
        kind: "unauthorized_privilege_change",
        severity: "high",
        status: "awaiting_approval",
        occurredAt: "2026-08-27T12:00:00.000Z",
        summaryCode: "PRIVILEGE_CHANGE_REQUIRES_REVIEW",
        planHashVersion: 1,
        planHash: plan.planHash,
        actionTypes: plan.actions.map((action) => action.type),
      });
      let failAuditInsert = true;
      const faultStore: OperationalStore = {
        execute: (statement) => store.execute(statement),
        transaction: (operation) =>
          store.transaction((tx) =>
            operation({
              execute: async (statement) => {
                if (
                  failAuditInsert &&
                  statement.sql.includes("INSERT INTO timeline_events")
                ) {
                  failAuditInsert = false;
                  throw new Error("audit insert unavailable");
                }
                return tx.execute(statement);
              },
              batch: (statements) => tx.batch(statements),
            }),
          ),
        close: () => {},
      };
      await expect(
        deliverExternalIncident(
          faultStore,
          providerBeforeRestart,
          {
            operation: "open-awaiting-approval",
            projection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          {
            clock,
            ids: sequenceIdGenerator(["rolled-back-provider-audit"]),
          },
        ),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      const rolledBack = await store.execute({
        sql: `SELECT status, attempt_count, external_ref,
          (SELECT count(*) FROM timeline_events
            WHERE type = 'provider.incident_delivery') AS audit_count
          FROM provider_deliveries`,
      });
      expect(rolledBack.rows[0]).toEqual({
        status: "delivering",
        attempt_count: 1,
        external_ref: null,
        audit_count: 0,
      });
      now = "2026-08-27T12:02:03.000Z";
      const providerAfterRestart = new MockIncidentProvider({ store });
      await expect(
        deliverExternalIncident(
          store,
          providerAfterRestart,
          {
            operation: "open-awaiting-approval",
            projection,
            workflowRunId: "run-1",
            correlationId: "correlation-1",
          },
          {
            clock,
            ids: sequenceIdGenerator(["reconciled-provider-audit"]),
          },
        ),
      ).resolves.toMatchObject({ status: "succeeded", attemptCount: 2 });
      const reconciled = await store.execute({
        sql: `SELECT status, attempt_count, external_ref,
          (SELECT count(*) FROM timeline_events
            WHERE type = 'provider.incident_delivery') AS audit_count
          FROM provider_deliveries`,
      });
      expect(reconciled.rows[0]).toMatchObject({
        status: "succeeded",
        attempt_count: 2,
        audit_count: 1,
      });
      expect(providerBeforeRestart.calls).toHaveLength(1);
      expect(providerAfterRestart.calls).toHaveLength(0);
    } finally {
      store.close();
    }
  });
});

function mockState(): MockContainmentState {
  return {
    sessions: new Map(),
    roles: new Map(),
    devices: new Map(),
    reauthentication: new Map(),
    calls: new Map(),
  };
}

function gatewayFor(
  store: Awaited<ReturnType<typeof setup>>["store"],
  state: MockContainmentState,
  mode: "mock" | "staging" | "production" = "mock",
) {
  return new ContainmentGateway({
    store,
    state,
    mode,
    timeoutMs: 1_000,
    rateLimit: 8,
    clock: fixedClock("2026-08-27T12:03:00.000Z"),
  });
}
