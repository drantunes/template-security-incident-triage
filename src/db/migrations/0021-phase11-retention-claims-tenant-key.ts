/** Makes retention claims tenant-local without weakening withheld legacy claims. */
export const phase11RetentionClaimsTenantKeyStatements = [
  `ALTER TABLE retention_tombstone_claims RENAME TO retention_tombstone_claims_legacy_withheld`,
  `CREATE TABLE retention_tombstone_claims (
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 128),
    source_identity TEXT NOT NULL CHECK(json_valid(source_identity)),
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    retention_class TEXT NOT NULL CHECK(retention_class IN ('thirty-day','three-hundred-sixty-five-day')),
    disposition TEXT NOT NULL CHECK(disposition IN ('deleted','minimized','retained-authority')),
    aged_at TEXT NOT NULL CHECK(aged_at GLOB '????-??-??T??:??:??.???Z'),
    tombstoned_at TEXT NOT NULL CHECK(tombstoned_at GLOB '????-??-??T??:??:??.???Z'),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    PRIMARY KEY(source, tenant_id, source_identity)
  ) STRICT`,
  `CREATE INDEX idx_retention_tombstone_claims_tenant_v2 ON retention_tombstone_claims(tenant_id, tombstoned_at)`,
  `CREATE TRIGGER retention_tombstone_claims_v2_append_only_update BEFORE UPDATE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstone_claims_v2_append_only_delete BEFORE DELETE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `INSERT INTO retention_tombstone_claims(
    source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
  ) SELECT source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
    FROM retention_tombstone_claims_legacy_withheld WHERE tenant_id IS NOT NULL`,
] as const;
