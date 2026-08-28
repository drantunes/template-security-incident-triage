import type { InValue } from "@libsql/client";

import type { OperationalStore } from "../db/operational-store.js";
import { DomainError } from "../domain/errors.js";
import {
  decodeCursor,
  encodeCursor,
  type DashboardTimelineEvent,
} from "./contracts.js";
import { redactTimelinePayload } from "./redaction.js";
import {
  Phase5ResultSchema,
  ValidatedContainmentPlanSchema,
} from "../triage/decision-contracts.js";
import { calculatePlanHash } from "../containment/plan-canonicalization.js";

type Row = Record<string, InValue>;
type DashboardQueryStore = Pick<OperationalStore, "execute">;

export async function listDashboardIncidents(
  store: OperationalStore,
  input: Readonly<{
    tenantId: string;
    limit: number;
    kind?: string;
    status?: string;
    severity?: string;
    cursor?: string;
    cursorSecret: string;
  }>,
) {
  const filters = JSON.stringify({
    kind: input.kind ?? null,
    status: input.status ?? null,
    severity: input.severity ?? null,
  });
  const cursor = input.cursor
    ? decodeCursor(
        input.cursor,
        { tenantId: input.tenantId, filters },
        input.cursorSecret,
      )
    : null;
  if (input.cursor && !cursor) throw new DomainError("VALIDATION_FAILED");
  const clauses = ["tenant_id = ?"];
  const args: InValue[] = [input.tenantId];
  for (const [column, value] of [
    ["kind", input.kind],
    ["status", input.status],
    ["severity", input.severity],
  ] as const) {
    if (value) {
      clauses.push(`${column} = ?`);
      args.push(value);
    }
  }
  if (cursor) {
    clauses.push("(updated_at < ? OR (updated_at = ? AND id < ?))");
    args.push(cursor.updatedAt, cursor.updatedAt, cursor.incidentId);
  }
  args.push(input.limit + 1);
  const result = await store.execute({
    sql: `SELECT id, kind, severity, status, subject_id, current_run_id, created_at, updated_at
      FROM incidents WHERE ${clauses.join(" AND ")}
      ORDER BY updated_at DESC, id DESC LIMIT ?`,
    args,
  });
  const rows = result.rows.slice(0, input.limit) as Row[];
  const items = rows.map((row) => ({
    incidentId: String(row.id),
    kind: String(row.kind),
    severity: row.severity === null ? null : String(row.severity),
    status: String(row.status),
    subjectRef: String(row.subject_id),
    workflowRunId:
      row.current_run_id === null ? null : String(row.current_run_id),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  }));
  const next = result.rows.length > input.limit ? rows.at(-1) : undefined;
  return {
    items,
    page: {
      limit: input.limit,
      nextCursor: next
        ? encodeCursor(
            {
              updatedAt: String(next.updated_at),
              incidentId: String(next.id),
              tenantId: input.tenantId,
              filters,
            },
            input.cursorSecret,
          )
        : null,
    },
  };
}

export async function readDashboardIncident(
  store: OperationalStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
) {
  return store.transaction((tx) => readDashboardIncidentSnapshot(tx, input));
}

/**
 * All reads which form a detail DTO share one LibSQL transaction snapshot.
 * This prevents a committed approval/timeline from being combined with the
 * pre-commit incident pointer or containment plan.
 */
async function readDashboardIncidentSnapshot(
  store: DashboardQueryStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
) {
  const incident = await store.execute({
    sql: `SELECT id, kind, severity, status, subject_id, current_run_id, current_plan_id, created_at, updated_at FROM incidents WHERE tenant_id = ? AND id = ?`,
    args: [input.tenantId, input.incidentId],
  });
  const row = incident.rows[0] as Row | undefined;
  if (!row) throw new DomainError("NOT_FOUND");
  // The cursor is deliberately derived from the same bounded read as the
  // rendered timeline. A separate MAX(sequence) can observe an event which
  // was not in the DOM snapshot, causing the browser to skip it on replay.
  const timelineSnapshot = await readDashboardTimelineSnapshot(
    store,
    input,
    200,
  );
  const [evidence, plan, approval, actions, workflow] = await Promise.all([
    store.execute({
      sql: `SELECT id, source, provider, observed_at, collected_at, confidence, incomplete, error_code FROM evidence_items WHERE tenant_id = ? AND incident_id = ? ORDER BY observed_at LIMIT 200`,
      args: [input.tenantId, input.incidentId],
    }),
    store.execute({
      sql: `SELECT id, plan_version, plan_hash_version, plan_hash, expires_at, plan_json FROM containment_plans WHERE tenant_id = ? AND incident_id = ? AND id = ?`,
      args: [input.tenantId, input.incidentId, row.current_plan_id ?? ""],
    }),
    store.execute({
      sql: `SELECT id, plan_id, plan_hash_version, plan_hash, decision, decided_at, decision_reason, expires_at FROM approvals WHERE tenant_id = ? AND incident_id = ? AND plan_id = ? ORDER BY requested_at DESC LIMIT 1`,
      args: [input.tenantId, input.incidentId, row.current_plan_id ?? ""],
    }),
    store.execute({
      sql: `SELECT action_id, action_type, status, result_ref FROM containment_actions WHERE tenant_id = ? AND incident_id = ? AND plan_id = ? ORDER BY ordinal`,
      args: [input.tenantId, input.incidentId, row.current_plan_id ?? ""],
    }),
    store.execute({
      sql: `SELECT phase5_result_json FROM workflow_runs WHERE tenant_id = ? AND incident_id = ? AND run_id = ?`,
      args: [input.tenantId, input.incidentId, row.current_run_id ?? ""],
    }),
  ]);
  const phase5 = parsePhase5Result(workflow.rows[0]?.phase5_result_json);
  const canonicalPlan = parseCanonicalPlan(plan.rows[0]?.plan_json);
  if (plan.rows[0]) {
    if (
      !canonicalPlan ||
      canonicalPlan.planId !== String(plan.rows[0].id) ||
      canonicalPlan.incidentId !== input.incidentId ||
      canonicalPlan.tenantId !== input.tenantId ||
      canonicalPlan.planHash !== String(plan.rows[0].plan_hash) ||
      calculatePlanHash(canonicalPlan) !== canonicalPlan.planHash ||
      canonicalPlan.planHashVersion !==
        Number(plan.rows[0].plan_hash_version) ||
      canonicalPlan.expiresAt !== String(plan.rows[0].expires_at) ||
      !phase5 ||
      phase5.status !== "ready-for-approval" ||
      phase5.plan.planHash !== canonicalPlan.planHash ||
      phase5.plan.planId !== canonicalPlan.planId ||
      !sameActions(phase5.plan.actions, canonicalPlan.actions) ||
      !sameActions(
        canonicalPlan.actions,
        actions.rows.map((action) => ({
          actionId: String(action.action_id),
          type: String(action.action_type),
        })),
      )
    )
      throw new DomainError("NOT_FOUND");
    const approvalRow = approval.rows[0];
    if (
      approvalRow &&
      (String(approvalRow.plan_id) !== canonicalPlan.planId ||
        Number(approvalRow.plan_hash_version) !==
          canonicalPlan.planHashVersion ||
        String(approvalRow.plan_hash) !== canonicalPlan.planHash ||
        String(approvalRow.expires_at) !== canonicalPlan.expiresAt)
    )
      throw new DomainError("NOT_FOUND");
  }
  const projectedActions = actions.rows.map((item) => ({
    actionId: String(item.action_id),
    type: String(item.action_type),
    status: String(item.status),
    resultRef: null,
  }));
  const completed = projectedActions.filter(
    (action) => action.status === "completed",
  ).length;
  const failed = projectedActions.filter(
    (action) => action.status === "failed",
  ).length;
  return {
    incident: {
      incidentId: String(row.id),
      kind: String(row.kind),
      severity: row.severity === null ? null : String(row.severity),
      status: String(row.status),
      subjectRef: String(row.subject_id),
      workflowRunId:
        row.current_run_id === null ? null : String(row.current_run_id),
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at),
    },
    evidence: evidence.rows.map((item) => ({
      evidenceId: String(item.id),
      source: String(item.source),
      provider: String(item.provider),
      observedAt: String(item.observed_at),
      collectedAt: String(item.collected_at),
      confidence: Number(item.confidence),
      state: Number(item.incomplete) === 1 ? "missing" : "fact",
      errorCode: item.error_code === null ? null : "EVIDENCE_UNAVAILABLE",
    })),
    timeline: timelineSnapshot.timeline,
    timelineCursor: `${input.incidentId}:${timelineSnapshot.cursor}`,
    plan:
      plan.rows[0] && canonicalPlan
        ? {
            planId: String(plan.rows[0].id),
            version: Number(plan.rows[0].plan_version),
            planHashVersion: Number(plan.rows[0].plan_hash_version),
            planHash: String(plan.rows[0].plan_hash),
            expiresAt: String(plan.rows[0].expires_at),
          }
        : null,
    approval: approval.rows[0]
      ? {
          approvalId: String(approval.rows[0].id),
          decision:
            approval.rows[0].decision === null
              ? null
              : String(approval.rows[0].decision),
          decidedAt:
            approval.rows[0].decided_at === null
              ? null
              : String(approval.rows[0].decided_at),
          reason:
            approval.rows[0].decision_reason === null
              ? null
              : String(approval.rows[0].decision_reason).slice(0, 2000),
          expiresAt: String(approval.rows[0].expires_at),
        }
      : null,
    actions: projectedActions,
    outcome: {
      status:
        failed > 0 && completed > 0
          ? "partial"
          : failed > 0
            ? "failed"
            : completed === projectedActions.length && completed > 0
              ? "completed"
              : "pending",
      completedCount: completed,
      failedCount: failed,
    },
    triage:
      phase5?.status === "ready-for-approval" && Boolean(canonicalPlan)
        ? {
            summary: phase5.summary.summary,
            facts: phase5.summary.facts.map((fact) => fact.text),
            hypotheses: phase5.summary.hypotheses.map(
              (hypothesis) => hypothesis.text,
            ),
            runbook: phase5.decision.runbookReference,
            actions: canonicalPlan!.actions.map((action) => ({
              actionId: action.actionId,
              type: action.type,
              targetRef: action.targetId,
              impact: action.impact,
              preconditions: action.preconditions,
              rollback: action.rollback,
              verification: action.verification,
            })),
          }
        : null,
  };
}

/** Lightweight tenant-scoped handshake validation for SSE. */
export async function dashboardIncidentExists(
  store: OperationalStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
): Promise<boolean> {
  const result = await store.execute({
    sql: "SELECT 1 FROM incidents WHERE tenant_id = ? AND id = ? LIMIT 1",
    args: [input.tenantId, input.incidentId],
  });
  return result.rows.length === 1;
}

export async function dashboardLastTimelineSequence(
  store: OperationalStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
): Promise<number> {
  const result = await store.execute({
    sql: "SELECT MAX(sequence) AS sequence FROM timeline_events WHERE tenant_id = ? AND incident_id = ?",
    args: [input.tenantId, input.incidentId],
  });
  const sequence = result.rows[0]?.sequence;
  return sequence === null || sequence === undefined ? 0 : Number(sequence);
}

export async function listDashboardTimeline(
  store: OperationalStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
  afterSequence: number,
  limit: number,
): Promise<readonly DashboardTimelineEvent[]> {
  const result = await store.execute({
    sql: `SELECT t.sequence, t.type, t.occurred_at, t.payload_json, i.current_run_id FROM timeline_events t JOIN incidents i ON i.tenant_id = t.tenant_id AND i.id = t.incident_id WHERE t.tenant_id = ? AND t.incident_id = ? AND t.sequence > ? ORDER BY t.sequence LIMIT ?`,
    args: [input.tenantId, input.incidentId, afterSequence, limit],
  });
  return result.rows.map((row) => ({
    incidentId: input.incidentId,
    workflowRunId:
      row.current_run_id === null ? null : String(row.current_run_id),
    sequence: Number(row.sequence),
    type: String(row.type),
    occurredAt: String(row.occurred_at),
    payloadRedacted: redactTimelinePayload(parsePayload(row.payload_json)),
  }));
}

/** The detail snapshot is a bounded current window, not the oldest events. */
export async function listDashboardRecentTimeline(
  store: OperationalStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
  limit: number,
): Promise<readonly DashboardTimelineEvent[]> {
  const result = await store.execute({
    sql: `SELECT * FROM (SELECT t.sequence, t.type, t.occurred_at, t.payload_json, i.current_run_id FROM timeline_events t JOIN incidents i ON i.tenant_id = t.tenant_id AND i.id = t.incident_id WHERE t.tenant_id = ? AND t.incident_id = ? ORDER BY t.sequence DESC LIMIT ?) ORDER BY sequence ASC`,
    args: [input.tenantId, input.incidentId, limit],
  });
  return result.rows.map((row) => ({
    incidentId: input.incidentId,
    workflowRunId:
      row.current_run_id === null ? null : String(row.current_run_id),
    sequence: Number(row.sequence),
    type: String(row.type),
    occurredAt: String(row.occurred_at),
    payloadRedacted: redactTimelinePayload(parsePayload(row.payload_json)),
  }));
}

/**
 * Reads the current bounded timeline window and its replay cursor at one
 * database boundary. The cursor is the last returned event, never a later
 * global maximum, so a concurrent append is replayed rather than skipped.
 */
export async function readDashboardTimelineSnapshot(
  store: DashboardQueryStore,
  input: Readonly<{ tenantId: string; incidentId: string }>,
  limit: number,
): Promise<
  Readonly<{ timeline: readonly DashboardTimelineEvent[]; cursor: number }>
> {
  const result = await store.execute({
    sql: `/* dashboard_timeline_snapshot */ SELECT * FROM (SELECT t.sequence, t.type, t.occurred_at, t.payload_json, i.current_run_id FROM timeline_events t JOIN incidents i ON i.tenant_id = t.tenant_id AND i.id = t.incident_id WHERE t.tenant_id = ? AND t.incident_id = ? ORDER BY t.sequence DESC LIMIT ?) ORDER BY sequence ASC`,
    args: [input.tenantId, input.incidentId, limit],
  });
  const timeline = result.rows.map((row) => ({
    incidentId: input.incidentId,
    workflowRunId:
      row.current_run_id === null ? null : String(row.current_run_id),
    sequence: Number(row.sequence),
    type: String(row.type),
    occurredAt: String(row.occurred_at),
    payloadRedacted: redactTimelinePayload(parsePayload(row.payload_json)),
  }));
  return { timeline, cursor: timeline.at(-1)?.sequence ?? 0 };
}

function parsePayload(value: unknown): unknown {
  try {
    return typeof value === "string" ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}

function parsePhase5Result(value: unknown) {
  try {
    return typeof value === "string"
      ? (Phase5ResultSchema.safeParse(JSON.parse(value)).data ?? null)
      : null;
  } catch {
    return null;
  }
}

function parseCanonicalPlan(value: unknown) {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : null;
    const result = ValidatedContainmentPlanSchema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

function sameActions(
  left: readonly { actionId: string; type: string }[],
  right: readonly { actionId: string; type: string }[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (action, index) =>
        action.actionId === right[index]?.actionId &&
        action.type === right[index]?.type,
    )
  );
}
