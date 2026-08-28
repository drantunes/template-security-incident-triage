import { DomainError } from "../domain/errors.js";
import type { ContainmentAction } from "../schemas/containment.js";
import type { MockContainmentState } from "./mock-state.js";

export class MockPreconditionError extends Error {}

export function assertMockPrecondition(
  state: MockContainmentState,
  action: ContainmentAction,
): void {
  if (action.type === "revoke_session") {
    const current = state.sessions.get(action.targetId);
    if (current !== undefined && current !== "active" && current !== "revoked")
      throw new MockPreconditionError();
    return;
  }
  if (action.type === "restore_previous_role") {
    const role = action.input.role;
    if (role !== "member" && role !== "viewer") fail();
    const current = state.roles.get(action.targetId);
    if (current !== undefined && current !== "admin" && current !== role)
      throw new MockPreconditionError();
    return;
  }
  if (action.type === "mark_device_for_review") {
    if (action.input.reviewState !== "pending") fail();
    const current = state.devices.get(action.targetId);
    if (current !== undefined && current !== "clear" && current !== "pending")
      throw new MockPreconditionError();
    return;
  }
  const sessionId = action.input.sessionId;
  if (typeof sessionId !== "string") fail();
  const current = state.reauthentication.get(action.targetId);
  if (current !== undefined && current !== sessionId)
    throw new MockPreconditionError();
}

function fail(): never {
  throw new DomainError("VALIDATION_FAILED");
}
