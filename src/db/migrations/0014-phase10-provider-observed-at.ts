/**
 * Diego-authorised, forward-only correction for Phase 10 analytics.
 *
 * `next_attempt_at` is a scheduler field, not evidence of when a provider
 * state was observed.  New writes therefore carry an explicit operational
 * timestamp. Historical terminal rows that lack one remain NULL: the export
 * is deliberately fail-closed rather than manufacturing 1970 or wall time.
 */
export const phase10ProviderObservedAtStatements = [
  `ALTER TABLE provider_deliveries ADD COLUMN observed_at TEXT
    CHECK(observed_at IS NULL OR observed_at GLOB '????-??-??T??:??:??.???Z')`,
  `DROP TRIGGER phase10_export_provider_insert`,
  `DROP TRIGGER phase10_export_provider_update`,
  `CREATE TRIGGER phase10_export_provider_insert AFTER INSERT ON provider_deliveries
    WHEN NEW.observed_at IS NOT NULL
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('provider_deliveries', NEW.id, printf('%s:%s:observed-v2', NEW.attempt_count, NEW.status), NEW.observed_at,
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.observed_at,'category',NEW.operation,'status',NEW.status,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_provider_update AFTER UPDATE ON provider_deliveries
    WHEN NEW.observed_at IS NOT NULL
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('provider_deliveries', NEW.id, printf('%s:%s:observed-v2', NEW.attempt_count, NEW.status), NEW.observed_at,
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.observed_at,'category',NEW.operation,'status',NEW.status,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
] as const;
