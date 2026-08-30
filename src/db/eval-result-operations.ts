import { createHash } from "node:crypto";

import type { OperationalStore } from "./operational-store.js";

export async function persistSanitizedEvalResult(
  store: OperationalStore,
  input: Readonly<{
    id: string;
    datasetVersion: string;
    caseId: string;
    evalId: string;
    scorerVersion: string;
    tenantId: string;
    incidentId?: string;
    workflowRunId?: string;
    /** Sanitised independent labels used for the Phase 10 confusion ledger. */
    expectedDisposition?: string;
    observedDisposition?: string;
    expectedSeverity?: string;
    observedSeverity?: string;
    passed: boolean;
    numerator: number;
    denominator: number;
    recordedAt: string;
  }>,
): Promise<void> {
  const resultHash = createHash("sha256")
    .update(
      JSON.stringify({
        id: input.id,
        datasetVersion: input.datasetVersion,
        caseId: input.caseId,
        evalId: input.evalId,
        scorerVersion: input.scorerVersion,
        tenantId: input.tenantId,
        incidentId: input.incidentId ?? null,
        workflowRunId: input.workflowRunId ?? null,
        expectedDisposition: input.expectedDisposition ?? null,
        observedDisposition: input.observedDisposition ?? null,
        expectedSeverity: input.expectedSeverity ?? null,
        observedSeverity: input.observedSeverity ?? null,
        passed: input.passed,
        numerator: input.numerator,
        denominator: input.denominator,
        recordedAt: input.recordedAt,
      }),
    )
    .digest("hex");
  const existing = await store.execute({
    sql: `SELECT result_hash FROM eval_results WHERE dataset_version=? AND case_id=? AND eval_id=? AND scorer_version=?`,
    args: [
      input.datasetVersion,
      input.caseId,
      input.evalId,
      input.scorerVersion,
    ],
  });
  if (existing.rows.length) {
    if (existing.rows[0]?.result_hash !== resultHash)
      throw new Error("PHASE10_EVAL_RESULT_CONFLICT");
    return;
  }
  await store.execute({
    sql: `INSERT INTO eval_results(
      id,dataset_version,case_id,eval_id,scorer_version,tenant_id,incident_id,workflow_run_id,expected_disposition,observed_disposition,expected_severity,observed_severity,passed,numerator,denominator,result_hash,recorded_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    args: [
      input.id,
      input.datasetVersion,
      input.caseId,
      input.evalId,
      input.scorerVersion,
      input.tenantId,
      input.incidentId ?? null,
      input.workflowRunId ?? null,
      input.expectedDisposition ?? null,
      input.observedDisposition ?? null,
      input.expectedSeverity ?? null,
      input.observedSeverity ?? null,
      input.passed ? 1 : 0,
      input.numerator,
      input.denominator,
      resultHash,
      input.recordedAt,
    ],
  });
}

/** Reads back the append-only official score ledger; callers must not trust
 * an in-memory scorer result as publication evidence. */
export async function readSanitizedEvalResults(
  store: OperationalStore,
  input: Readonly<{ datasetVersion: string; caseId: string }>,
): Promise<
  readonly Readonly<{
    evalId: string;
    scorerVersion: string;
    expectedDisposition?: string;
    observedDisposition?: string;
    expectedSeverity?: string;
    observedSeverity?: string;
    passed: boolean;
    numerator: number;
    denominator: number;
  }>[]
> {
  const rows = await store.execute({
    sql: `SELECT eval_id,scorer_version,expected_disposition,observed_disposition,expected_severity,observed_severity,passed,numerator,denominator
      FROM eval_results WHERE dataset_version=? AND case_id=?
      ORDER BY eval_id,scorer_version`,
    args: [input.datasetVersion, input.caseId],
  });
  return Object.freeze(
    rows.rows.map((row) => ({
      evalId: String(row.eval_id),
      scorerVersion: String(row.scorer_version),
      expectedDisposition:
        row.expected_disposition === null
          ? undefined
          : String(row.expected_disposition),
      observedDisposition:
        row.observed_disposition === null
          ? undefined
          : String(row.observed_disposition),
      expectedSeverity:
        row.expected_severity === null
          ? undefined
          : String(row.expected_severity),
      observedSeverity:
        row.observed_severity === null
          ? undefined
          : String(row.observed_severity),
      passed: Number(row.passed) === 1,
      numerator: Number(row.numerator),
      denominator: Number(row.denominator),
    })),
  );
}
