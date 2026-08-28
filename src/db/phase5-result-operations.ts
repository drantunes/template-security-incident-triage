import { createHash } from "node:crypto";

import { canonicalizePlanValue } from "../containment/plan-canonicalization.js";
import { DomainError, parseDomainSchema } from "../domain/errors.js";
import {
  Phase5ResultSchema,
  type Phase5Result,
} from "../triage/decision-contracts.js";
import type {
  OperationalStore,
  StoreTransaction,
} from "./operational-store.js";

export function canonicalPhase5Result(result: Phase5Result): string {
  return canonicalizePlanValue(parseDomainSchema(Phase5ResultSchema, result));
}

export function phase5ResultHash(canonical: string): string {
  return createHash("sha256").update(canonical).digest("hex");
}

export async function persistAuthoritativePhase5Result(
  store: OperationalStore,
  input: Readonly<{
    tenantId: string;
    incidentId: string;
    workflowRunId: string;
    result: Phase5Result;
  }>,
): Promise<void> {
  const canonical = canonicalPhase5Result(input.result);
  const digest = phase5ResultHash(canonical);
  const updated = await store.execute({
    sql: `UPDATE workflow_runs SET phase5_result_json = ?, phase5_result_hash = ?
      WHERE tenant_id = ? AND incident_id = ? AND run_id = ?
        AND (phase5_result_json IS NULL OR
          (phase5_result_json = ? AND phase5_result_hash = ?))`,
    args: [
      canonical,
      digest,
      input.tenantId,
      input.incidentId,
      input.workflowRunId,
      canonical,
      digest,
    ],
  });
  if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
}

export async function readAuthoritativePhase5Result(
  tx: StoreTransaction,
  input: Readonly<{
    tenantId: string;
    incidentId: string;
    workflowRunId: string;
  }>,
): Promise<Phase5Result> {
  const result = await tx.execute({
    sql: `SELECT phase5_result_json, phase5_result_hash FROM workflow_runs
      WHERE tenant_id = ? AND incident_id = ? AND run_id = ?`,
    args: [input.tenantId, input.incidentId, input.workflowRunId],
  });
  const row = result.rows[0];
  if (!row?.phase5_result_json || !row.phase5_result_hash) {
    throw new DomainError("CONFLICT");
  }
  const canonical = String(row.phase5_result_json);
  if (phase5ResultHash(canonical) !== row.phase5_result_hash) {
    throw new DomainError("VALIDATION_FAILED");
  }
  try {
    const parsed = parseDomainSchema(Phase5ResultSchema, JSON.parse(canonical));
    if (canonicalPhase5Result(parsed) !== canonical) {
      throw new DomainError("VALIDATION_FAILED");
    }
    return parsed;
  } catch (error) {
    if (error instanceof DomainError) throw error;
    throw new DomainError("VALIDATION_FAILED");
  }
}
