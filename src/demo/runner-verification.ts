import type { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import {
  calculatePlanHash,
  canonicalizePlanValue,
} from "../containment/plan-canonicalization.js";
import {
  Phase5ResultSchema,
  ValidatedContainmentPlanSchema,
} from "../triage/decision-contracts.js";
import type { DemoJournal } from "./contracts.js";
import { fixtureForScenario, scenarioDetailsFor } from "./fixtures.js";
import { throwIfAborted } from "./lifecycle-state.js";
import { verifyActionProjection } from "./runner-projections.js";

export async function verifyExpiredTerminal(
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

export async function verifyTerminal(
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
