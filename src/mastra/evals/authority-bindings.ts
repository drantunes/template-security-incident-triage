import { sha256Canonical, type Phase10Input } from "./dataset-contract.js";

/**
 * Stable binding used by the operational containment-plan record.  It derives
 * only from the input fixture and the domain action, never from ground truth
 * or an evaluated payload.
 */
export function phase10PlanHash(
  input: Phase10Input,
  action: string,
  target: string,
): string {
  return sha256Canonical({
    caseId: input.caseId,
    tenantAlias: input.fixture.tenantAlias,
    incidentAlias: input.fixture.incidentAlias,
    action,
    target,
    runbook: input.fixture.runbook,
  });
}

export function phase10ActionForInput(input: Phase10Input): string {
  return input.scenario === "privilege"
    ? "restore_previous_role"
    : "revoke_session";
}
