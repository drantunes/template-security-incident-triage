/** C1 approved v1; v2 adds audited, non-metric cursor tombstones. */
export const analyticsSchemaVersion = 2;
export const analyticsSchemaChecksum =
  "phase10-analytics-schema-v2-journal-tombstone-cursor-scenario";

export const analyticsSchemaStatements = [
  `CREATE TABLE IF NOT EXISTS analytics_schema_versions(version INTEGER PRIMARY KEY, checksum VARCHAR NOT NULL, applied_at VARCHAR NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS ingest_cursors(source VARCHAR PRIMARY KEY, last_sequence BIGINT NOT NULL, last_source_id VARCHAR NOT NULL, schema_version INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS analytics_ingest_state(id INTEGER PRIMARY KEY CHECK(id=1), last_sequence BIGINT NOT NULL, record_count BIGINT NOT NULL, checksum VARCHAR NOT NULL, schema_version INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS analytics_withheld_events(sequence BIGINT PRIMARY KEY, source VARCHAR NOT NULL, source_id VARCHAR NOT NULL, source_version VARCHAR NOT NULL, reason VARCHAR NOT NULL, checksum VARCHAR NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS analytics_facts(source VARCHAR NOT NULL, source_id VARCHAR NOT NULL, source_version VARCHAR NOT NULL, sequence BIGINT NOT NULL UNIQUE, tenant_id VARCHAR NOT NULL, incident_id VARCHAR, occurred_at TIMESTAMPTZ NOT NULL, category VARCHAR NOT NULL, status VARCHAR, scenario VARCHAR, checksum VARCHAR NOT NULL, PRIMARY KEY(source, source_id, source_version))`,
  `CREATE VIEW IF NOT EXISTS provider_delivery_current AS SELECT * EXCLUDE (row_number) FROM (SELECT *, row_number() OVER (PARTITION BY source,source_id ORDER BY sequence DESC) AS row_number FROM analytics_facts WHERE source='provider_deliveries') WHERE row_number=1`,
  `CREATE VIEW IF NOT EXISTS approval_current AS SELECT * EXCLUDE (row_number) FROM (SELECT *, row_number() OVER (PARTITION BY source,source_id ORDER BY sequence DESC) AS row_number FROM analytics_facts WHERE source='approvals') WHERE row_number=1`,
  `CREATE VIEW IF NOT EXISTS eval_case_results AS SELECT * FROM analytics_facts WHERE source='eval_results'`,
  `CREATE VIEW IF NOT EXISTS timeline_event_facts AS SELECT * FROM analytics_facts WHERE source='timeline_events'`,
] as const;
