/**
 * Phase 11 retention ledger. Existing authority tables are intentionally not
 * rebuilt or weakened: a tombstone records when a retained authority reaches
 * policy age, while deletion/minimisation applies only to data without a
 * durable authority dependency.
 */
export const phase11RetentionStatements = [
  `CREATE TABLE retention_audit_events (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    event TEXT NOT NULL CHECK(event IN ('started','completed')),
    dry_run INTEGER NOT NULL CHECK(dry_run IN (0,1)),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z'),
    detail_json TEXT NOT NULL CHECK(json_valid(detail_json))
  ) STRICT`,
  `CREATE INDEX idx_retention_audit_sweep ON retention_audit_events(sweep_id, occurred_at)`,
  `CREATE TABLE retention_tombstones (
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 128),
    source_id TEXT NOT NULL CHECK(length(trim(source_id)) BETWEEN 1 AND 256),
    tenant_id TEXT CHECK(tenant_id IS NULL OR length(trim(tenant_id)) BETWEEN 1 AND 128),
    retention_class TEXT NOT NULL CHECK(retention_class IN ('thirty-day','three-hundred-sixty-five-day')),
    disposition TEXT NOT NULL CHECK(disposition IN ('deleted','minimized','retained-authority')),
    aged_at TEXT NOT NULL CHECK(aged_at GLOB '????-??-??T??:??:??.???Z'),
    tombstoned_at TEXT NOT NULL CHECK(tombstoned_at GLOB '????-??-??T??:??:??.???Z'),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    PRIMARY KEY(source, source_id)
  ) STRICT`,
  `CREATE INDEX idx_retention_tombstones_tenant ON retention_tombstones(tenant_id, tombstoned_at)`,
  `CREATE TRIGGER retention_audit_events_append_only_update BEFORE UPDATE ON retention_audit_events
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_audit_events_append_only_delete BEFORE DELETE ON retention_audit_events
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstones_append_only_update BEFORE UPDATE ON retention_tombstones
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstones_append_only_delete BEFORE DELETE ON retention_tombstones
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
] as const;
