/**
 * Rebuild retention-owned tenant indexes with the canonical operational
 * boundary: byte-exact, non-empty and at most 128 characters. Existing rows
 * that cannot prove that boundary remain in their renamed legacy tables;
 * their identity is never inferred into a tenant-scoped sweep.
 */
export const phase11RetentionTenantBoundaryStatements = [
  `ALTER TABLE retention_source_cursors RENAME TO retention_source_cursors_legacy_withheld`,
  `CREATE TABLE retention_source_cursors (
    tenant_id TEXT PRIMARY KEY CHECK(length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id),
    next_source INTEGER NOT NULL CHECK(next_source >= 0)
  ) STRICT`,
  `INSERT INTO retention_source_cursors(tenant_id, next_source)
    SELECT tenant_id, next_source FROM retention_source_cursors_legacy_withheld
    WHERE length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id`,
  `ALTER TABLE retention_tombstone_claims RENAME TO retention_tombstone_claims_v21_legacy_withheld`,
  `CREATE TABLE retention_tombstone_claims (
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 128),
    source_identity TEXT NOT NULL CHECK(json_valid(source_identity)),
    tenant_id TEXT NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id),
    retention_class TEXT NOT NULL CHECK(retention_class IN ('thirty-day','three-hundred-sixty-five-day')),
    disposition TEXT NOT NULL CHECK(disposition IN ('deleted','minimized','retained-authority')),
    aged_at TEXT NOT NULL CHECK(aged_at GLOB '????-??-??T??:??:??.???Z'),
    tombstoned_at TEXT NOT NULL CHECK(tombstoned_at GLOB '????-??-??T??:??:??.???Z'),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    PRIMARY KEY(source, tenant_id, source_identity)
  ) STRICT`,
  `CREATE INDEX idx_retention_tombstone_claims_tenant_v22 ON retention_tombstone_claims(tenant_id, tombstoned_at)`,
  `CREATE TRIGGER retention_tombstone_claims_v22_append_only_update BEFORE UPDATE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstone_claims_v22_append_only_delete BEFORE DELETE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `INSERT INTO retention_tombstone_claims(
    source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
  ) SELECT source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
    FROM retention_tombstone_claims_v21_legacy_withheld
    WHERE length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id`,
] as const;
