import { ContainmentPlanSchema } from "../schemas/containment.js";
import { DomainError, parseDomainSchema } from "../domain/errors.js";
import type { Clock } from "../domain/clock.js";
import { systemClock } from "../domain/clock.js";
import type { IdGenerator } from "../domain/id-generator.js";
import type { OperationalStore } from "../db/operational-store.js";
import { getIncident, transitionIncident } from "../db/incident-operations.js";
import { recordContainmentOutcome } from "../db/containment-outcome-operations.js";
import { ContainmentGateway } from "./gateway.js";
import type { MockContainmentState } from "./mock-state.js";

export async function retryPartialContainment(
  store: OperationalStore,
  input: Readonly<{
    tenantId: string;
    incidentId: string;
    workflowRunId: string;
    approvalId: string;
    correlationId: string;
    state: MockContainmentState;
    mode: "mock" | "staging" | "production";
    timeoutMs: number;
    rateLimit: number;
  }>,
  dependencies: Readonly<{ clock?: Clock; ids?: IdGenerator }> = {},
) {
  const clock = dependencies.clock ?? systemClock;
  const binding = await store.execute({
    sql: `SELECT i.status, i.current_plan_id, i.current_run_id,
      a.plan_id, a.plan_hash, a.plan_hash_version, a.expires_at,
      a.decision, a.decided_by_role, p.plan_json
      FROM incidents i JOIN approvals a
        ON a.tenant_id = i.tenant_id AND a.incident_id = i.id
      JOIN containment_plans p
        ON p.tenant_id = a.tenant_id AND p.incident_id = a.incident_id
        AND p.id = a.plan_id
      WHERE i.tenant_id = ? AND i.id = ? AND a.id = ?
        AND a.workflow_run_id = ?`,
    args: [
      input.tenantId,
      input.incidentId,
      input.approvalId,
      input.workflowRunId,
    ],
  });
  const row = binding.rows[0];
  if (
    !row ||
    !["failed", "containing"].includes(String(row.status)) ||
    row.current_plan_id !== row.plan_id ||
    row.current_run_id !== input.workflowRunId ||
    row.decision !== "approved" ||
    row.decided_by_role !== "soc_manager" ||
    String(row.expires_at) <= clock.now()
  ) {
    throw new DomainError("CONFLICT");
  }
  let plan: unknown;
  try {
    plan = JSON.parse(String(row.plan_json));
  } catch {
    throw new DomainError("VALIDATION_FAILED");
  }
  const parsedPlan = parseDomainSchema(ContainmentPlanSchema, plan);
  if (row.status === "failed") {
    const before = await getIncident(store, input.tenantId, input.incidentId);
    await transitionIncident(
      store,
      {
        tenantId: input.tenantId,
        incidentId: input.incidentId,
        expectedVersion: before.version,
        to: "containing",
        runId: input.workflowRunId,
        correlationId: input.correlationId,
        causationId: input.approvalId,
        payload: { recovery: "partial-retry" },
      },
      dependencies,
    );
  }
  const gateway = new ContainmentGateway({
    store,
    state: input.state,
    mode: input.mode,
    timeoutMs: input.timeoutMs,
    rateLimit: input.rateLimit,
    ...dependencies,
  });
  const outcomes = [];
  for (const action of parsedPlan.actions) {
    const outcome = await gateway.executeApprovedAction({
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      workflowRunId: input.workflowRunId,
      approvalId: input.approvalId,
      plan: parsedPlan,
      action,
    });
    outcomes.push(outcome);
    if (outcome.status !== "completed" || outcome.verification !== "verified") {
      break;
    }
  }
  const failed = outcomes.some(
    (outcome) =>
      outcome.status !== "completed" || outcome.verification !== "verified",
  );
  const completedCount = outcomes.filter(
    (outcome) =>
      outcome.status === "completed" && outcome.verification === "verified",
  ).length;
  const current = await getIncident(store, input.tenantId, input.incidentId);
  await recordContainmentOutcome(
    store,
    {
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      workflowRunId: input.workflowRunId,
      correlationId: input.correlationId,
      approvalId: input.approvalId,
      expectedVersion: current.version,
      status: failed ? "failed" : "contained",
      partial: failed && completedCount > 0,
      completedCount,
      failedCount: failed ? 1 : 0,
    },
    dependencies,
  );
  if (!failed) {
    const contained = await getIncident(
      store,
      input.tenantId,
      input.incidentId,
    );
    await transitionIncident(
      store,
      {
        tenantId: input.tenantId,
        incidentId: input.incidentId,
        expectedVersion: contained.version,
        to: "closed",
        runId: input.workflowRunId,
        correlationId: input.correlationId,
        causationId: input.approvalId,
        payload: { recovery: "partial-retry-complete" },
      },
      dependencies,
    );
  }
  return Object.freeze({ status: failed ? "failed" : "contained", outcomes });
}
