import type { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { canonicalizePlanValue } from "../containment/plan-canonicalization.js";
import { ExternalIncidentProjectionSchema } from "../providers/incident-provider.js";
import type { DemoJournal, DemoScenario } from "./contracts.js";
import { fixtureForScenario } from "./fixtures.js";

export async function verifyActionProjection(
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
