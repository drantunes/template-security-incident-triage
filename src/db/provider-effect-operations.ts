import { DomainError } from "../domain/errors.js";
import type { OperationalStore } from "./operational-store.js";

export type ProviderEffectBinding = Readonly<{
  provider: "workos";
  tenantId: string;
  incidentId: string;
  approvalId: string;
  subjectId: string;
  planId: string;
  actionId: string;
  targetId: string;
  idempotencyKey: string;
  fenceToken: string;
  operation: "revoke_session" | "restore_previous_role";
  now: string;
}>;

export async function claimProviderEffect(
  store: OperationalStore,
  input: ProviderEffectBinding,
): Promise<"claimed" | "succeeded" | "uncertain" | "in_flight"> {
  return store.transaction(async (tx) => {
    const active = await tx.execute({
      sql: `SELECT action.action_type, action.target_id, action.idempotency_key,
          incident.subject_id, attempt.approval_id
        FROM containment_action_attempts attempt
        JOIN containment_actions action ON action.tenant_id = attempt.tenant_id
          AND action.incident_id = attempt.incident_id AND action.plan_id = attempt.plan_id
          AND action.action_id = attempt.action_id
        JOIN incidents incident ON incident.tenant_id = attempt.tenant_id
          AND incident.id = attempt.incident_id
        WHERE attempt.tenant_id = ? AND attempt.incident_id = ? AND attempt.plan_id = ? AND attempt.action_id = ?
          AND attempt.approval_id = ? AND attempt.fence_token = ?
          AND attempt.status = 'executing' AND attempt.lease_expires_at > ?`,
      args: [
        input.tenantId,
        input.incidentId,
        input.planId,
        input.actionId,
        input.approvalId,
        input.fenceToken,
        input.now,
      ],
    });
    const authoritative = active.rows[0];
    if (
      !authoritative ||
      authoritative.action_type !== input.operation ||
      authoritative.target_id !== input.targetId ||
      authoritative.idempotency_key !== input.idempotencyKey ||
      authoritative.subject_id !== input.subjectId ||
      authoritative.approval_id !== input.approvalId
    )
      throw new DomainError("VALIDATION_FAILED");
    const inserted = await tx.execute({
      sql: `INSERT OR IGNORE INTO provider_effect_ledger(
        provider, idempotency_key, tenant_id, incident_id, operation, plan_id, action_id,
        target_id, status, fence_token, claimed_at
      ) VALUES ('workos', ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?)`,
      args: [
        input.idempotencyKey,
        input.tenantId,
        input.incidentId,
        input.operation,
        input.planId,
        input.actionId,
        input.targetId,
        input.fenceToken,
        input.now,
      ],
    });
    const row = await tx.execute({
      sql: `SELECT tenant_id, incident_id, operation, plan_id, action_id, target_id,
        fence_token, status FROM provider_effect_ledger
        WHERE provider = 'workos' AND idempotency_key = ?`,
      args: [input.idempotencyKey],
    });
    let effect = row.rows[0];
    if (
      !effect ||
      effect.tenant_id !== input.tenantId ||
      effect.incident_id !== input.incidentId ||
      effect.operation !== input.operation ||
      effect.plan_id !== input.planId ||
      effect.action_id !== input.actionId ||
      effect.target_id !== input.targetId ||
      (effect.fence_token !== input.fenceToken && effect.status !== "uncertain")
    )
      throw new DomainError("CONFLICT");
    // A new F6 attempt may only inherit an ambiguous, already-dispatched
    // effect. It receives the new fence solely to perform read-only
    // reconciliation; the provider's uncertain branch never issues mutation.
    if (
      effect.status === "uncertain" &&
      effect.fence_token !== input.fenceToken
    ) {
      const moved = await tx.execute({
        sql: `UPDATE provider_effect_ledger SET fence_token = ?
          WHERE provider = 'workos' AND idempotency_key = ?
            AND status = 'uncertain' AND fence_token = ?`,
        args: [
          input.fenceToken,
          input.idempotencyKey,
          String(effect.fence_token),
        ],
      });
      if (moved.rowsAffected !== 1) throw new DomainError("CONFLICT");
      effect = { ...effect, fence_token: input.fenceToken };
    }
    if (effect.status === "succeeded") return "succeeded";
    if (effect.status === "uncertain") return "uncertain";
    // A duplicate claimant must never send another mutation while the first
    // caller still owns the provider effect.  There is intentionally no
    // "steal" path: only independent provider reconciliation resolves it.
    return inserted.rowsAffected === 1 ? "claimed" : "in_flight";
  });
}

export async function finishProviderEffect(
  store: OperationalStore,
  input: Readonly<{
    idempotencyKey: string;
    fenceToken: string;
    status: "succeeded" | "uncertain" | "failed";
    externalRef?: string;
    now: string;
  }>,
): Promise<void> {
  const updated = await store.execute({
    sql: `UPDATE provider_effect_ledger SET status = ?, external_ref = ?, completed_at = ?
      WHERE provider = 'workos' AND idempotency_key = ? AND fence_token = ?
        AND status = 'claimed'`,
    args: [
      input.status,
      input.externalRef ?? null,
      input.status === "uncertain" ? null : input.now,
      input.idempotencyKey,
      input.fenceToken,
    ],
  });
  if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
}

export async function reconcileProviderEffect(
  store: OperationalStore,
  input: Readonly<{
    idempotencyKey: string;
    fenceToken: string;
    succeeded: boolean;
    now: string;
  }>,
): Promise<"succeeded" | "uncertain"> {
  if (!input.succeeded) return "uncertain";
  const updated = await store.execute({
    sql: `UPDATE provider_effect_ledger SET status = 'succeeded', completed_at = ?
      WHERE provider = 'workos' AND idempotency_key = ? AND fence_token = ?
        AND status = 'uncertain'`,
    args: [input.now, input.idempotencyKey, input.fenceToken],
  });
  if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
  return "succeeded";
}
