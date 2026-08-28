export const evidenceIntegrityVersionStatements = [
  `ALTER TABLE evidence_items
    ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1 CHECK(hash_version = 1)`,
] as const;
