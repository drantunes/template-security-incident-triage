import { finishContainmentAction } from "./execution-claims.js";
import {
  authorizeGatewayAction,
  type GatewayActionInput,
} from "./gateway-authorization.js";
import { readContainmentOutcome } from "./containment-verification.js";
import { ActionTimeoutError, withActionTimeout } from "./action-timeout.js";
import type { MockContainmentState } from "./mock-state.js";
import {
  assertMockPrecondition,
  MockPreconditionError,
} from "./mock-preconditions.js";
import type { OperationalStore } from "../db/operational-store.js";
import type { Clock } from "../domain/clock.js";
import { systemClock } from "../domain/clock.js";
import { DomainError } from "../domain/errors.js";
import type { IdGenerator } from "../domain/id-generator.js";
import {
  ContainmentActionOutcomeSchema,
  type ContainmentAction,
  type ContainmentActionOutcome,
} from "../schemas/containment.js";

export class ContainmentGateway {
  constructor(
    private readonly dependencies: Readonly<{
      store: OperationalStore;
      state: MockContainmentState;
      mode: "mock" | "staging" | "production";
      timeoutMs: number;
      rateLimit: number;
      clock?: Clock;
      ids?: IdGenerator;
    }>,
  ) {}

  async executeApprovedAction(
    input: GatewayActionInput,
  ): Promise<ContainmentActionOutcome> {
    const clock = this.dependencies.clock ?? systemClock;
    const authorization = await authorizeGatewayAction(
      this.dependencies.store,
      input,
      this.dependencies,
    );
    if (authorization.state === "replayed") return authorization.outcome;
    const { plan, action } = authorization;
    const fence = {
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      planId: plan.planId,
      actionId: action.actionId,
      fenceToken: authorization.fenceToken,
    };
    try {
      if (
        authorization.attempt > 1 &&
        (await verifyMockEffect(
          this.dependencies.store,
          this.dependencies.state,
          fence,
          action,
          clock,
        ))
      ) {
        const reconciled = ContainmentActionOutcomeSchema.parse({
          actionId: action.actionId,
          status: "completed",
          verification: "verified",
          providerRef: `mock-action-${action.actionId}`,
        });
        await finishContainmentAction(
          this.dependencies.store,
          {
            tenantId: input.tenantId,
            planId: plan.planId,
            actionId: action.actionId,
            fenceToken: authorization.fenceToken,
            status: reconciled.status,
            verification: reconciled.verification,
            providerRef: reconciled.providerRef,
          },
          { clock },
        );
        return reconciled;
      }
      const providerRef = await withActionTimeout(
        executeMockEffect(
          this.dependencies.store,
          this.dependencies.state,
          fence,
          action,
          clock,
        ),
        this.dependencies.timeoutMs,
      );
      const verified = await verifyMockEffect(
        this.dependencies.store,
        this.dependencies.state,
        fence,
        action,
        clock,
      );
      const outcome = ContainmentActionOutcomeSchema.parse(
        verified
          ? {
              actionId: action.actionId,
              status: "completed",
              verification: "verified",
              providerRef,
            }
          : {
              actionId: action.actionId,
              status: "failed",
              verification: "not_verified",
              providerRef,
              errorCode: "VERIFICATION_FAILED",
            },
      );
      await finishContainmentAction(
        this.dependencies.store,
        {
          tenantId: input.tenantId,
          planId: plan.planId,
          actionId: action.actionId,
          fenceToken: authorization.fenceToken,
          status: outcome.status,
          verification: outcome.verification,
          ...(outcome.providerRef ? { providerRef: outcome.providerRef } : {}),
          ...(outcome.errorCode ? { errorCode: outcome.errorCode } : {}),
        },
        { clock },
      );
      return outcome;
    } catch (error) {
      const timedOut = error instanceof ActionTimeoutError;
      const preconditionFailed = error instanceof MockPreconditionError;
      if (!timedOut && !preconditionFailed) {
        try {
          if (
            await verifyMockEffect(
              this.dependencies.store,
              this.dependencies.state,
              fence,
              action,
              clock,
            )
          ) {
            const recovered = ContainmentActionOutcomeSchema.parse({
              actionId: action.actionId,
              status: "completed",
              verification: "verified",
              providerRef: `mock-action-${action.actionId}`,
            });
            await finishContainmentAction(
              this.dependencies.store,
              {
                tenantId: input.tenantId,
                planId: plan.planId,
                actionId: action.actionId,
                fenceToken: authorization.fenceToken,
                status: recovered.status,
                verification: recovered.verification,
                providerRef: recovered.providerRef,
              },
              { clock },
            );
            return recovered;
          }
        } catch {
          // The closed failure below remains authoritative and redacted.
        }
      }
      const outcome = ContainmentActionOutcomeSchema.parse({
        actionId: action.actionId,
        status: timedOut
          ? "timed_out"
          : preconditionFailed
            ? "blocked"
            : "failed",
        verification: "not_run",
        errorCode: timedOut
          ? "PROVIDER_TIMEOUT"
          : preconditionFailed
            ? "PRECONDITION_FAILED"
            : "PROVIDER_FAILED",
      });
      await finishContainmentAction(
        this.dependencies.store,
        {
          tenantId: input.tenantId,
          planId: plan.planId,
          actionId: action.actionId,
          fenceToken: authorization.fenceToken,
          status: outcome.status,
          verification: outcome.verification,
          errorCode: outcome.errorCode,
        },
        { clock },
      );
      return outcome;
    }
  }

  async verifyApprovedAction(
    input: Parameters<ContainmentGateway["executeApprovedAction"]>[0],
  ) {
    return readContainmentOutcome(this.dependencies.store, input);
  }
}

type DurableFence = Readonly<{
  tenantId: string;
  incidentId: string;
  planId: string;
  actionId: string;
  fenceToken: string;
}>;

async function assertActiveFence(
  store: OperationalStore,
  fence: DurableFence,
  clock: Clock,
): Promise<void> {
  const result = await store.execute({
    sql: `SELECT 1 FROM containment_action_attempts attempt
      JOIN containment_actions action
        ON action.tenant_id = attempt.tenant_id
        AND action.incident_id = attempt.incident_id
        AND action.plan_id = attempt.plan_id
        AND action.action_id = attempt.action_id
      WHERE attempt.tenant_id = ? AND attempt.incident_id = ?
        AND attempt.plan_id = ? AND attempt.action_id = ?
        AND attempt.fence_token = ? AND attempt.status = 'executing'
        AND attempt.lease_expires_at > ? AND action.status = 'executing'
        AND attempt.attempt = (
          SELECT max(latest.attempt) FROM containment_action_attempts latest
          WHERE latest.tenant_id = attempt.tenant_id
            AND latest.plan_id = attempt.plan_id
            AND latest.action_id = attempt.action_id
        )`,
    args: [
      fence.tenantId,
      fence.incidentId,
      fence.planId,
      fence.actionId,
      fence.fenceToken,
      clock.now(),
    ],
  });
  if (!result.rows[0]) fail();
}

async function executeMockEffect(
  store: OperationalStore,
  state: MockContainmentState,
  fence: DurableFence,
  action: ContainmentAction,
  clock: Clock,
): Promise<string> {
  await assertActiveFence(store, fence, clock);
  if (state.delayMs) {
    await new Promise<void>((resolve) => setTimeout(resolve, state.delayMs));
  }
  await assertActiveFence(store, fence, clock);
  assertMockPrecondition(state, action);
  if (state.failActions?.has(action.actionId)) {
    state.calls.set(
      action.actionId,
      (state.calls.get(action.actionId) ?? 0) + 1,
    );
    throw new DomainError("STORAGE_UNAVAILABLE", { retryable: true });
  }
  const inputJson = JSON.stringify(action.input);
  const providerRef = `mock-action-${action.actionId}`;
  const inserted = await store.transaction(async (tx) => {
    const result = await tx.execute({
      sql: `INSERT OR IGNORE INTO mock_containment_effects(
        tenant_id, incident_id, plan_id, action_id, action_type, target_id,
        input_json, attempt, fence_token, provider_ref, applied_at
      ) SELECT ?, ?, ?, ?, ?, ?, ?, attempt.attempt, attempt.fence_token, ?, ?
        FROM containment_action_attempts attempt
        JOIN containment_actions persisted
          ON persisted.tenant_id = attempt.tenant_id
          AND persisted.incident_id = attempt.incident_id
          AND persisted.plan_id = attempt.plan_id
          AND persisted.action_id = attempt.action_id
        WHERE attempt.tenant_id = ? AND attempt.incident_id = ?
          AND attempt.plan_id = ? AND attempt.action_id = ?
          AND attempt.fence_token = ? AND attempt.status = 'executing'
          AND attempt.lease_expires_at > ? AND persisted.status = 'executing'
          AND attempt.attempt = (
            SELECT max(latest.attempt) FROM containment_action_attempts latest
            WHERE latest.tenant_id = attempt.tenant_id
              AND latest.plan_id = attempt.plan_id
              AND latest.action_id = attempt.action_id
          )`,
      args: [
        fence.tenantId,
        fence.incidentId,
        fence.planId,
        fence.actionId,
        action.type,
        action.targetId,
        inputJson,
        providerRef,
        clock.now(),
        fence.tenantId,
        fence.incidentId,
        fence.planId,
        fence.actionId,
        fence.fenceToken,
        clock.now(),
      ],
    });
    if (result.rowsAffected === 1) return true;
    const existing = await tx.execute({
      sql: `SELECT action_type, target_id, input_json, provider_ref
        FROM mock_containment_effects
        WHERE tenant_id = ? AND incident_id = ? AND plan_id = ? AND action_id = ?`,
      args: [fence.tenantId, fence.incidentId, fence.planId, fence.actionId],
    });
    const row = existing.rows[0];
    if (
      !row ||
      row.action_type !== action.type ||
      row.target_id !== action.targetId ||
      row.input_json !== inputJson ||
      row.provider_ref !== providerRef
    ) {
      fail();
    }
    return false;
  });
  if (!inserted) return providerRef;
  state.calls.set(action.actionId, (state.calls.get(action.actionId) ?? 0) + 1);
  applyMockMirror(state, action);
  if (state.failAfterEffectActions?.has(action.actionId)) {
    throw new DomainError("STORAGE_UNAVAILABLE", { retryable: true });
  }
  return providerRef;
}

function applyMockMirror(
  state: MockContainmentState,
  action: ContainmentAction,
): void {
  if (action.type === "revoke_session") {
    state.sessions.set(action.targetId, "revoked");
  } else if (action.type === "restore_previous_role") {
    state.roles.set(action.targetId, String(action.input.role));
  } else if (action.type === "mark_device_for_review") {
    state.devices.set(action.targetId, "pending");
  } else {
    state.reauthentication.set(action.targetId, String(action.input.sessionId));
  }
}

async function verifyMockEffect(
  store: OperationalStore,
  state: MockContainmentState,
  fence: DurableFence,
  action: ContainmentAction,
  clock: Clock,
): Promise<boolean> {
  await assertActiveFence(store, fence, clock);
  if (state.verificationFailures?.has(action.actionId)) return false;
  const result = await store.execute({
    sql: `SELECT action_type, target_id, input_json, provider_ref
      FROM mock_containment_effects
      WHERE tenant_id = ? AND incident_id = ? AND plan_id = ? AND action_id = ?`,
    args: [fence.tenantId, fence.incidentId, fence.planId, fence.actionId],
  });
  const row = result.rows[0];
  if (!row) return false;
  if (
    row.action_type !== action.type ||
    row.target_id !== action.targetId ||
    row.input_json !== JSON.stringify(action.input) ||
    row.provider_ref !== `mock-action-${action.actionId}`
  ) {
    fail();
  }
  return true;
}

function fail(): never {
  throw new DomainError("VALIDATION_FAILED");
}
