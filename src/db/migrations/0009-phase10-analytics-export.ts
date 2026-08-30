/**
 * Public, sanitised change journal for the Phase 10 read model.  It exposes
 * only identity/version metadata; the analytics exporter projects a strict
 * allowlist from the four public SOC tables in a separate read transaction.
 */
export const phase10AnalyticsExportStatements = [
  `CREATE TABLE eval_results (
    id TEXT PRIMARY KEY,
    dataset_version TEXT NOT NULL,
    case_id TEXT NOT NULL,
    eval_id TEXT NOT NULL,
    scorer_version TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    incident_id TEXT,
    workflow_run_id TEXT,
    expected_disposition TEXT,
    observed_disposition TEXT,
    expected_severity TEXT,
    observed_severity TEXT,
    passed INTEGER NOT NULL CHECK(passed IN (0,1)),
    numerator INTEGER NOT NULL CHECK(numerator >= 0),
    denominator INTEGER NOT NULL CHECK(denominator >= 0),
    result_hash TEXT NOT NULL CHECK(length(result_hash) = 64 AND result_hash NOT GLOB '*[^0-9a-f]*'),
    recorded_at TEXT NOT NULL CHECK(recorded_at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE(dataset_version, case_id, eval_id, scorer_version)
  ) STRICT`,
  `CREATE TABLE analytics_export_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL CHECK(source IN ('timeline_events','provider_deliveries','approvals','eval_results')),
    source_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    changed_at TEXT NOT NULL CHECK(changed_at GLOB '????-??-??T??:??:??.???Z'),
    snapshot_json TEXT NOT NULL
  ) STRICT`,
  `CREATE INDEX idx_analytics_export_events_cursor
    ON analytics_export_events(sequence, source, source_id)`,
  `CREATE TRIGGER phase10_eval_results_no_update BEFORE UPDATE ON eval_results
    BEGIN SELECT RAISE(ABORT, 'PHASE10_APPEND_ONLY'); END`,
  `CREATE TRIGGER phase10_eval_results_no_delete BEFORE DELETE ON eval_results
    BEGIN SELECT RAISE(ABORT, 'PHASE10_APPEND_ONLY'); END`,
  `CREATE TRIGGER phase10_export_events_no_update BEFORE UPDATE ON analytics_export_events
    BEGIN SELECT RAISE(ABORT, 'PHASE10_APPEND_ONLY'); END`,
  `CREATE TRIGGER phase10_export_events_no_delete BEFORE DELETE ON analytics_export_events
    BEGIN SELECT RAISE(ABORT, 'PHASE10_APPEND_ONLY'); END`,
  `CREATE TRIGGER phase10_export_timeline_insert AFTER INSERT ON timeline_events
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', NEW.id, CAST(NEW.schema_version AS TEXT), NEW.occurred_at,
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.occurred_at,'category',CASE NEW.type WHEN 'triage.validation.completed' THEN 'triage.completed' WHEN 'triage.validation.blocked' THEN 'guardrail.plan_attempt' ELSE NEW.type END,'status',CASE NEW.type WHEN 'triage.validation.blocked' THEN 'blocked:' || COALESCE(json_extract(NEW.payload_json,'$.reasonCodes'),'unknown') ELSE COALESCE(json_extract(NEW.payload_json,'$.status'),json_extract(NEW.payload_json,'$.decision')) END,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_provider_insert AFTER INSERT ON provider_deliveries
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('provider_deliveries', NEW.id, printf('%s:%s', NEW.attempt_count, NEW.status), COALESCE(NEW.next_attempt_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.next_attempt_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),'category',NEW.operation,'status',NEW.status,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_provider_update AFTER UPDATE ON provider_deliveries
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('provider_deliveries', NEW.id, printf('%s:%s', NEW.attempt_count, NEW.status), COALESCE(NEW.next_attempt_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.next_attempt_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')),'category',NEW.operation,'status',NEW.status,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_approval_insert AFTER INSERT ON approvals
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('approvals', NEW.id, printf('%s:%s', COALESCE(NEW.decided_at, NEW.requested_at), COALESCE(NEW.decision, 'pending')), NEW.requested_at,
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.requested_at,'category','approval','status',COALESCE(NEW.decision,'pending'),'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_approval_update AFTER UPDATE ON approvals
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('approvals', NEW.id, printf('%s:%s', COALESCE(NEW.decided_at, NEW.expiry_resumed_at, NEW.requested_at), CASE WHEN NEW.decision IS NULL AND NEW.expiry_resumed_at IS NOT NULL THEN 'expired' ELSE COALESCE(NEW.decision, 'pending') END), COALESCE(NEW.decided_at, NEW.expiry_resumed_at, NEW.requested_at),
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.decided_at,NEW.expiry_resumed_at,NEW.requested_at),'category','approval','status',CASE WHEN NEW.decision IS NULL AND NEW.expiry_resumed_at IS NOT NULL THEN 'expired' ELSE COALESCE(NEW.decision,'pending') END,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_guardrail_plan AFTER INSERT ON containment_plans
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', 'guardrail:' || NEW.id, CAST(NEW.plan_version AS TEXT), NEW.created_at,
      json_object('id','guardrail:' || NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.created_at,'category','guardrail.plan_attempt','status','allowed','scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_containment_attempt_insert AFTER INSERT ON containment_action_attempts
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', 'containment:' || NEW.id, CAST(NEW.attempt AS TEXT), NEW.started_at,
      json_object('id','containment:' || NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.started_at,'category','containment.attempt','status',NEW.status || ':' || NEW.verification,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_containment_attempt_update AFTER UPDATE ON containment_action_attempts
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', 'containment:' || NEW.id, CAST(NEW.attempt AS TEXT) || ':' || NEW.status || ':' || NEW.verification, COALESCE(NEW.finished_at, NEW.started_at),
      json_object('id','containment:' || NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.finished_at,NEW.started_at),'category','containment.attempt','status',NEW.status || ':' || NEW.verification,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_guardrail_action_blocked_insert AFTER INSERT ON containment_action_attempts
    WHEN NEW.status='blocked'
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', 'guardrail-action:' || NEW.id, CAST(NEW.attempt AS TEXT) || ':' || COALESCE(NEW.error_code,'ACTION_BLOCKED'), COALESCE(NEW.finished_at, NEW.started_at),
      json_object('id','guardrail-action:' || NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.finished_at,NEW.started_at),'category','guardrail.plan_attempt','status','blocked:' || COALESCE(NEW.error_code,'ACTION_BLOCKED'),'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_guardrail_action_blocked_update AFTER UPDATE ON containment_action_attempts
    WHEN NEW.status='blocked'
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('timeline_events', 'guardrail-action:' || NEW.id, CAST(NEW.attempt AS TEXT) || ':' || COALESCE(NEW.error_code,'ACTION_BLOCKED') || ':blocked', COALESCE(NEW.finished_at, NEW.started_at),
      json_object('id','guardrail-action:' || NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',COALESCE(NEW.finished_at,NEW.started_at),'category','guardrail.plan_attempt','status','blocked:' || COALESCE(NEW.error_code,'ACTION_BLOCKED'),'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `CREATE TRIGGER phase10_export_eval_insert AFTER INSERT ON eval_results
    BEGIN INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    VALUES ('eval_results', NEW.id, NEW.scorer_version, NEW.recorded_at,
      json_object('id',NEW.id,'tenant_id',NEW.tenant_id,'incident_id',NEW.incident_id,'occurred_at',NEW.recorded_at,'category',NEW.eval_id,'status',CASE NEW.passed WHEN 1 THEN 'passed' ELSE 'failed' END,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.incident_id))); END`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'timeline_events', id, CAST(schema_version AS TEXT), occurred_at,
      json_object('id',id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',occurred_at,'category',CASE type WHEN 'triage.validation.completed' THEN 'triage.completed' WHEN 'triage.validation.blocked' THEN 'guardrail.plan_attempt' ELSE type END,'status',CASE type WHEN 'triage.validation.blocked' THEN 'blocked:' || COALESCE(json_extract(payload_json,'$.reasonCodes'),'unknown') ELSE COALESCE(json_extract(payload_json,'$.status'),json_extract(payload_json,'$.decision')) END,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=timeline_events.tenant_id AND i.id=timeline_events.incident_id))
    FROM timeline_events ORDER BY occurred_at, id`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'provider_deliveries', id, printf('%s:%s', attempt_count, status),
      COALESCE(next_attempt_at, '1970-01-01T00:00:00.000Z'),
      json_object('id',id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',COALESCE(next_attempt_at,'1970-01-01T00:00:00.000Z'),'category',operation,'status',status,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=provider_deliveries.tenant_id AND i.id=provider_deliveries.incident_id))
    FROM provider_deliveries ORDER BY id`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'approvals', id, printf('%s:%s', COALESCE(decided_at, expiry_resumed_at, requested_at), CASE WHEN decision IS NULL AND expiry_resumed_at IS NOT NULL THEN 'expired' ELSE COALESCE(decision, 'pending') END), COALESCE(decided_at, expiry_resumed_at, requested_at)
      ,json_object('id',id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',COALESCE(decided_at,expiry_resumed_at,requested_at),'category','approval','status',CASE WHEN decision IS NULL AND expiry_resumed_at IS NOT NULL THEN 'expired' ELSE COALESCE(decision,'pending') END,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=approvals.tenant_id AND i.id=approvals.incident_id))
    FROM approvals ORDER BY requested_at, id`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'timeline_events', 'guardrail:' || id, CAST(plan_version AS TEXT), created_at,
      json_object('id','guardrail:' || id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',created_at,'category','guardrail.plan_attempt','status','allowed','scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=containment_plans.tenant_id AND i.id=containment_plans.incident_id))
    FROM containment_plans ORDER BY created_at, id`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'timeline_events', 'containment:' || id, CAST(attempt AS TEXT) || ':' || status || ':' || verification, COALESCE(finished_at, started_at),
      json_object('id','containment:' || id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',COALESCE(finished_at,started_at),'category','containment.attempt','status',status || ':' || verification,'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=containment_action_attempts.tenant_id AND i.id=containment_action_attempts.incident_id))
    FROM containment_action_attempts ORDER BY COALESCE(finished_at, started_at), id`,
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'timeline_events', 'guardrail-action:' || id, CAST(attempt AS TEXT) || ':' || COALESCE(error_code,'ACTION_BLOCKED') || ':blocked', COALESCE(finished_at, started_at),
      json_object('id','guardrail-action:' || id,'tenant_id',tenant_id,'incident_id',incident_id,'occurred_at',COALESCE(finished_at,started_at),'category','guardrail.plan_attempt','status','blocked:' || COALESCE(error_code,'ACTION_BLOCKED'),'scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=containment_action_attempts.tenant_id AND i.id=containment_action_attempts.incident_id))
    FROM containment_action_attempts WHERE status='blocked' ORDER BY COALESCE(finished_at, started_at), id`,
] as const;
