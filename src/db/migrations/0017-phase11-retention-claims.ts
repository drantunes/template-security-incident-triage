/**
 * Phase 11 retention claim identity. Migration 0016 used a short textual
 * source_id. This append-only successor stores the canonical JSON identity so
 * every ID permitted by the operational schema is claimable without delimiter
 * ambiguity or an artificial 256-character limit.
 */
export const phase11RetentionClaimsStatements = [
  `CREATE TABLE retention_tombstone_claims (
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 128),
    source_identity TEXT NOT NULL CHECK(json_valid(source_identity)),
    tenant_id TEXT CHECK(tenant_id IS NULL OR length(trim(tenant_id)) BETWEEN 1 AND 128),
    retention_class TEXT NOT NULL CHECK(retention_class IN ('thirty-day','three-hundred-sixty-five-day')),
    disposition TEXT NOT NULL CHECK(disposition IN ('deleted','minimized','retained-authority')),
    aged_at TEXT NOT NULL CHECK(aged_at GLOB '????-??-??T??:??:??.???Z'),
    tombstoned_at TEXT NOT NULL CHECK(tombstoned_at GLOB '????-??-??T??:??:??.???Z'),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    PRIMARY KEY(source, source_identity)
  ) STRICT`,
  `CREATE INDEX idx_retention_tombstone_claims_tenant ON retention_tombstone_claims(tenant_id, tombstoned_at)`,
  `CREATE TRIGGER retention_tombstone_claims_append_only_update BEFORE UPDATE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstone_claims_append_only_delete BEFORE DELETE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
] as const;
