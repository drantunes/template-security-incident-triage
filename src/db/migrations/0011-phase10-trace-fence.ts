/** Monotonic fence for the serialized Phase 10 trace continuation. */
export const phase10TraceFenceStatements = [
  `ALTER TABLE workflow_runs ADD COLUMN phase10_trace_version INTEGER NOT NULL DEFAULT 0`,
] as const;
