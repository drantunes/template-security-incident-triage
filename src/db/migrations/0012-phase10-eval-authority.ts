/** Durable Phase 10 authority bindings. Evidence and a selected runbook are
 * scoped to the workflow run that produced them; a later retry cannot relabel
 * either record as its own authority. */
export const phase10EvalAuthorityStatements = [
  `ALTER TABLE evidence_items ADD COLUMN workflow_run_id TEXT`,
  `CREATE INDEX idx_evidence_phase10_run ON evidence_items(tenant_id,incident_id,workflow_run_id,id)`,
  `CREATE TABLE phase10_runbook_authority (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    workflow_run_id TEXT NOT NULL,
    runbook_id TEXT NOT NULL,
    version TEXT NOT NULL,
    source_hash TEXT NOT NULL CHECK(length(source_hash)=64),
    selected_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id,incident_id,workflow_run_id),
    FOREIGN KEY(tenant_id,incident_id,workflow_run_id)
      REFERENCES workflow_runs(tenant_id,incident_id,run_id) ON DELETE RESTRICT,
    FOREIGN KEY(runbook_id,version) REFERENCES runbook_versions(runbook_id,version) ON DELETE RESTRICT
  ) STRICT`,
] as const;
