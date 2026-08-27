import {
  ApprovalDecisionSchema,
  ApprovalRequestSchema,
  type ApprovalDecision,
  type ApprovalRequest,
} from "../schemas/approval.js";
import {
  ContainmentPlanSchema,
  type ContainmentPlan,
} from "../schemas/containment.js";
import { DomainError, parseDomainSchema } from "../domain/errors.js";
import { systemClock, type Clock } from "../domain/clock.js";
import { uuidGenerator, type IdGenerator } from "../domain/id-generator.js";
import { utcTimestamp } from "../schemas/common.js";
import { insertTimelineAndOutbox } from "./incident-operations.js";
import type { OperationalStore } from "./operational-store.js";

export async function requestApproval(
  store: OperationalStore,
  input: Readonly<{
    plan: ContainmentPlan;
    approval: ApprovalRequest;
    expectedIncidentVersion: number;
    runId: string;
    correlationId: string;
  }>,
  dependencies: Readonly<{
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
): Promise<void> {
  const plan = parseDomainSchema(ContainmentPlanSchema, input.plan);
  const approval = parseDomainSchema(ApprovalRequestSchema, input.approval);
  const nowResult = utcTimestamp.safeParse(
    (dependencies.clock ?? systemClock).now(),
  );
  if (
    !nowResult.success ||
    approval.planId !== plan.planId ||
    approval.incidentId !== plan.incidentId ||
    approval.tenantId !== plan.tenantId ||
    approval.planHash !== plan.planHash ||
    approval.planHashVersion !== plan.planHashVersion ||
    approval.expiresAt !== plan.expiresAt ||
    plan.createdAt > approval.requestedAt ||
    approval.requestedAt > nowResult.data ||
    nowResult.data >= approval.expiresAt
  ) {
    throw new DomainError("VALIDATION_FAILED");
  }
  const ids = dependencies.ids ?? uuidGenerator;

  await store.transaction(async (tx) => {
    const updated = await tx.execute({
      sql: `UPDATE incidents SET status = 'awaiting_approval', version = version + 1,
        timeline_sequence = timeline_sequence + 1, current_plan_id = ?, updated_at = ?
        WHERE tenant_id = ? AND id = ? AND status = 'investigating' AND version = ?
          AND updated_at <= ?
        RETURNING timeline_sequence`,
      args: [
        plan.planId,
        approval.requestedAt,
        plan.tenantId,
        plan.incidentId,
        input.expectedIncidentVersion,
        approval.requestedAt,
      ],
    });
    const row = updated.rows[0];
    if (!row) throw new DomainError("CONFLICT");

    await tx.execute({
      sql: `INSERT INTO containment_plans(
        id, incident_id, tenant_id, schema_version, plan_version,
        plan_hash_version, plan_hash, plan_json, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        plan.planId,
        plan.incidentId,
        plan.tenantId,
        plan.schemaVersion,
        plan.planVersion,
        plan.planHashVersion,
        plan.planHash,
        JSON.stringify(plan),
        plan.expiresAt,
        plan.createdAt,
      ],
    });
    await tx.batch(
      plan.actions.map((action, ordinal) => ({
        sql: `INSERT INTO containment_actions(
          id, plan_id, incident_id, tenant_id, action_id, action_type, ordinal,
          input_json, idempotency_key, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
        args: [
          ids.next(),
          plan.planId,
          plan.incidentId,
          plan.tenantId,
          action.actionId,
          action.type,
          ordinal,
          JSON.stringify(action.input),
          `${plan.planId}:${action.actionId}`,
        ],
      })),
    );
    await tx.execute({
      sql: `INSERT INTO approvals(
        id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
        requested_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        approval.approvalId,
        approval.planId,
        approval.incidentId,
        approval.tenantId,
        approval.planHashVersion,
        approval.planHash,
        approval.requestedAt,
        approval.expiresAt,
      ],
    });
    await insertTimelineAndOutbox(tx, {
      timelineId: ids.next(),
      eventId: ids.next(),
      incidentId: plan.incidentId,
      tenantId: plan.tenantId,
      sequence: Number(row.timeline_sequence),
      type: "approval.requested",
      eventType: "security.approval.requested",
      runId: input.runId,
      correlationId: input.correlationId,
      occurredAt: approval.requestedAt,
      payload: { approvalId: approval.approvalId, planId: plan.planId },
    });
  });
}

export async function decideApproval(
  store: OperationalStore,
  input: Readonly<{
    decision: ApprovalDecision;
    expectedIncidentVersion: number;
    runId: string;
    correlationId: string;
  }>,
  dependencies: Readonly<{
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
): Promise<ApprovalDecision> {
  const decision = parseDomainSchema(ApprovalDecisionSchema, input.decision);
  const now = (dependencies.clock ?? systemClock).now();
  const ids = dependencies.ids ?? uuidGenerator;

  return store.transaction(async (tx) => {
    const result = await tx.execute({
      sql: `SELECT a.decision, a.decided_by, a.decided_by_role, a.decision_reason,
        a.decided_at, a.requested_at, a.expires_at, a.plan_hash, a.plan_hash_version,
        p.plan_hash AS containment_plan_hash,
        p.plan_hash_version AS containment_plan_hash_version,
        i.current_plan_id, i.updated_at AS incident_updated_at
        FROM approvals a
        JOIN containment_plans p
          ON p.tenant_id = a.tenant_id
          AND p.incident_id = a.incident_id
          AND p.id = a.plan_id
        JOIN incidents i
          ON i.tenant_id = a.tenant_id
          AND i.id = a.incident_id
        WHERE a.tenant_id = ? AND a.incident_id = ? AND a.plan_id = ? AND a.id = ?`,
      args: [
        decision.tenantId,
        decision.incidentId,
        decision.planId,
        decision.approvalId,
      ],
    });
    const current = result.rows[0];
    if (!current) throw new DomainError("NOT_FOUND");
    if (
      current.plan_hash !== decision.planHash ||
      Number(current.plan_hash_version) !== decision.planHashVersion ||
      current.containment_plan_hash !== decision.planHash ||
      Number(current.containment_plan_hash_version) !== decision.planHashVersion
    ) {
      throw new DomainError("CONFLICT");
    }
    if (current.decision !== null) {
      if (
        current.decision === decision.decision &&
        current.decided_by === decision.decidedBy &&
        current.decided_by_role === decision.decidedByRole &&
        current.decision_reason === (decision.reason ?? null)
      ) {
        return parseDomainSchema(ApprovalDecisionSchema, {
          ...decision,
          decidedAt: current.decided_at,
        });
      }
      throw new DomainError("CONFLICT");
    }
    if (current.current_plan_id !== decision.planId) {
      throw new DomainError("CONFLICT");
    }
    if (
      String(current.requested_at) > decision.decidedAt ||
      String(current.incident_updated_at) > decision.decidedAt ||
      decision.decidedAt > now ||
      String(current.expires_at) <= now
    ) {
      throw new DomainError("CONFLICT");
    }

    const approvalUpdate = await tx.execute({
      sql: `UPDATE approvals SET decision = ?, decided_by = ?, decided_by_role = ?,
        decision_reason = ?, decided_at = ?
        WHERE tenant_id = ? AND incident_id = ? AND plan_id = ? AND id = ?
          AND plan_hash_version = ? AND plan_hash = ? AND decision IS NULL`,
      args: [
        decision.decision,
        decision.decidedBy,
        decision.decidedByRole,
        decision.reason ?? null,
        decision.decidedAt,
        decision.tenantId,
        decision.incidentId,
        decision.planId,
        decision.approvalId,
        decision.planHashVersion,
        decision.planHash,
      ],
    });
    if (approvalUpdate.rowsAffected !== 1) throw new DomainError("CONFLICT");

    const incidentUpdate = await tx.execute({
      sql: `UPDATE incidents SET status = ?, version = version + 1,
        timeline_sequence = timeline_sequence + 1, updated_at = ?
        WHERE tenant_id = ? AND id = ? AND current_plan_id = ?
          AND status = 'awaiting_approval' AND version = ? AND updated_at <= ?
        RETURNING timeline_sequence`,
      args: [
        decision.decision,
        decision.decidedAt,
        decision.tenantId,
        decision.incidentId,
        decision.planId,
        input.expectedIncidentVersion,
        decision.decidedAt,
      ],
    });
    const incident = incidentUpdate.rows[0];
    if (!incident) throw new DomainError("CONFLICT");

    await insertTimelineAndOutbox(tx, {
      timelineId: ids.next(),
      eventId: ids.next(),
      incidentId: decision.incidentId,
      tenantId: decision.tenantId,
      sequence: Number(incident.timeline_sequence),
      type: "approval.decided",
      eventType: "security.approval.decided",
      runId: input.runId,
      correlationId: input.correlationId,
      causationId: decision.approvalId,
      occurredAt: decision.decidedAt,
      payload: {
        approvalId: decision.approvalId,
        decision: decision.decision,
        planId: decision.planId,
      },
    });
    return decision;
  });
}
