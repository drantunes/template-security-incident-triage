/**
 * The catalog is mutable by activation.  An evaluation needs the exact
 * successful retrieval, including its chunk citations and parsed procedure
 * rules, rather than whichever catalog version happens to be active later.
 */
export const phase10RunbookAuthoritySnapshotStatements = [
  `ALTER TABLE runbook_versions ADD COLUMN mandatory_rules_json TEXT`,
  `ALTER TABLE runbook_retrievals ADD COLUMN mandatory_rules_json TEXT`,
  `ALTER TABLE phase10_runbook_authority ADD COLUMN retrieval_id TEXT`,
  `ALTER TABLE phase10_runbook_authority ADD COLUMN generation_id TEXT`,
  `ALTER TABLE phase10_runbook_authority ADD COLUMN chunk_ids_json TEXT`,
  `ALTER TABLE phase10_runbook_authority ADD COLUMN mandatory_rules_json TEXT`,
  `ALTER TABLE phase10_runbook_authority ADD COLUMN allowed_actions_json TEXT`,
] as const;
