export const operationalSchemaStatements = [
  `CREATE TABLE incidents (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK(kind IN ('unauthorized_privilege_change','disallowed_country_login','unknown_device_login')),
    subject_id TEXT NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('received','investigating','awaiting_approval','approved','rejected','containing','contained','failed','closed')),
    severity TEXT CHECK(severity IS NULL OR severity IN ('low','medium','high','critical')),
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    timeline_sequence INTEGER NOT NULL DEFAULT 0 CHECK(timeline_sequence >= 0),
    current_plan_id TEXT,
    current_run_id TEXT,
    created_at TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??.???Z'),
    updated_at TEXT NOT NULL CHECK(updated_at GLOB '????-??-??T??:??:??.???Z'),
    closed_at TEXT CHECK(closed_at IS NULL OR closed_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK(updated_at >= created_at),
    CHECK(closed_at IS NULL OR closed_at >= created_at),
    UNIQUE(tenant_id, id),
    FOREIGN KEY(tenant_id, id, current_plan_id)
      REFERENCES containment_plans(tenant_id, incident_id, id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
  ) STRICT`,
  `CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('unauthorized_privilege_change','disallowed_country_login','unknown_device_login')),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z'),
    subject_id TEXT NOT NULL,
    canonical_json TEXT NOT NULL CHECK(json_valid(canonical_json)),
    raw_payload_ref TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    idempotency_key TEXT NOT NULL,
    UNIQUE(source, source_event_id),
    UNIQUE(tenant_id, idempotency_key),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE evidence_items (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('identity','endpoint','cloud','geoip','policy')),
    provider TEXT NOT NULL,
    observed_at TEXT NOT NULL CHECK(observed_at GLOB '????-??-??T??:??:??.???Z'),
    collected_at TEXT NOT NULL CHECK(collected_at GLOB '????-??-??T??:??:??.???Z'),
    fact_json TEXT NOT NULL CHECK(json_valid(fact_json)),
    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
    raw_payload_ref TEXT NOT NULL,
    integrity_hash TEXT NOT NULL CHECK(length(integrity_hash) = 64 AND integrity_hash NOT GLOB '*[^0-9a-f]*'),
    sensitivity TEXT NOT NULL CHECK(sensitivity IN ('public','internal','confidential','restricted')),
    incomplete INTEGER NOT NULL CHECK(incomplete IN (0,1)),
    error_code TEXT,
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE workflow_runs (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE,
    workflow_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL CHECK(started_at GLOB '????-??-??T??:??:??.???Z'),
    finished_at TEXT CHECK(finished_at IS NULL OR finished_at GLOB '????-??-??T??:??:??.???Z'),
    error_code TEXT,
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE containment_plans (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    plan_version INTEGER NOT NULL CHECK(plan_version > 0),
    plan_hash_version INTEGER NOT NULL CHECK(plan_hash_version > 0),
    plan_hash TEXT NOT NULL CHECK(length(plan_hash) = 64 AND plan_hash NOT GLOB '*[^0-9a-f]*'),
    plan_json TEXT NOT NULL CHECK(json_valid(plan_json)),
    expires_at TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??.???Z'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK(expires_at > created_at),
    UNIQUE(incident_id, plan_version),
    UNIQUE(plan_hash_version, plan_hash),
    UNIQUE(tenant_id, incident_id, id),
    UNIQUE(tenant_id, incident_id, id, plan_hash_version, plan_hash),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE containment_actions (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK(action_type IN ('revoke_session','restore_previous_role','mark_device_for_review','require_reauthentication')),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    input_json TEXT NOT NULL CHECK(json_valid(input_json)),
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    result_ref TEXT,
    UNIQUE(plan_id, action_id),
    UNIQUE(tenant_id, idempotency_key),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, plan_id)
      REFERENCES containment_plans(tenant_id, incident_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    plan_hash_version INTEGER NOT NULL CHECK(plan_hash_version > 0),
    plan_hash TEXT NOT NULL CHECK(length(plan_hash) = 64 AND plan_hash NOT GLOB '*[^0-9a-f]*'),
    requested_at TEXT NOT NULL CHECK(requested_at GLOB '????-??-??T??:??:??.???Z'),
    expires_at TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??.???Z'),
    decision TEXT CHECK(decision IS NULL OR decision IN ('approved','rejected')),
    decided_by TEXT,
    decided_by_role TEXT,
    decision_reason TEXT,
    decided_at TEXT CHECK(decided_at IS NULL OR decided_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK(expires_at > requested_at),
    CHECK(decided_at IS NULL OR (decided_at >= requested_at AND decided_at < expires_at)),
    CHECK((decision IS NULL AND decided_by IS NULL AND decided_by_role IS NULL AND decision_reason IS NULL AND decided_at IS NULL)
      OR (decision IS NOT NULL AND decided_by IS NOT NULL AND decided_by_role = 'soc_manager' AND decided_at IS NOT NULL)),
    CHECK(decision != 'rejected' OR length(decision_reason) > 0),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, plan_id, plan_hash_version, plan_hash)
      REFERENCES containment_plans(tenant_id, incident_id, id, plan_hash_version, plan_hash)
      ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE timeline_events (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    type TEXT NOT NULL CHECK(length(trim(type)) BETWEEN 1 AND 256),
    category TEXT NOT NULL CHECK(length(trim(category)) BETWEEN 1 AND 256),
    actor_id TEXT,
    correlation_id TEXT NOT NULL CHECK(length(trim(correlation_id)) BETWEEN 1 AND 128),
    causation_id TEXT CHECK(causation_id IS NULL OR length(trim(causation_id)) BETWEEN 1 AND 128),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE(incident_id, sequence),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE authorized_devices (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    authorized_at TEXT NOT NULL CHECK(authorized_at GLOB '????-??-??T??:??:??.???Z'),
    revoked_at TEXT CHECK(revoked_at IS NULL OR revoked_at GLOB '????-??-??T??:??:??.???Z'),
    metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
    UNIQUE(tenant_id, subject_id, device_id)
  ) STRICT`,
  `CREATE TABLE identity_snapshots (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
    snapshot_ref TEXT NOT NULL,
    integrity_hash TEXT NOT NULL CHECK(length(integrity_hash) = 64 AND integrity_hash NOT GLOB '*[^0-9a-f]*'),
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    captured_at TEXT NOT NULL CHECK(captured_at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE(tenant_id, subject_id, source_event_id)
  ) STRICT`,
  `CREATE TABLE provider_deliveries (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    next_attempt_at TEXT CHECK(next_attempt_at IS NULL OR next_attempt_at GLOB '????-??-??T??:??:??.???Z'),
    external_ref TEXT,
    error_code TEXT,
    UNIQUE(provider, incident_id, operation),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE outbox_events (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    type TEXT NOT NULL CHECK(type IN ('security.alert.received','security.workflow.updated','security.approval.requested','security.approval.decided','security.containment.completed','security.incident.updated','security.dead-letter')),
    run_id TEXT NOT NULL CHECK(length(trim(run_id)) BETWEEN 1 AND 128),
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    correlation_id TEXT NOT NULL CHECK(length(trim(correlation_id)) BETWEEN 1 AND 128),
    causation_id TEXT CHECK(causation_id IS NULL OR length(trim(causation_id)) BETWEEN 1 AND 128),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z'),
    available_at TEXT NOT NULL CHECK(available_at GLOB '????-??-??T??:??:??.???Z'),
    published_at TEXT CHECK(published_at IS NULL OR published_at GLOB '????-??-??T??:??:??.???Z'),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    error_code TEXT,
    UNIQUE(tenant_id, incident_id, id),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE dead_letter_events (
    id TEXT PRIMARY KEY,
    source_outbox_id TEXT,
    event_type TEXT NOT NULL,
    event_ref TEXT NOT NULL,
    tenant_id TEXT,
    incident_id TEXT,
    error_code TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK(attempt_count > 0),
    created_at TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??.???Z'),
    resolved_at TEXT CHECK(resolved_at IS NULL OR resolved_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK((tenant_id IS NULL) = (incident_id IS NULL)),
    CHECK(source_outbox_id IS NULL OR tenant_id IS NOT NULL),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, source_outbox_id)
      REFERENCES outbox_events(tenant_id, incident_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TRIGGER incidents_updated_at_monotonic
    BEFORE UPDATE OF updated_at ON incidents
    WHEN NEW.updated_at < OLD.updated_at
    BEGIN
      SELECT RAISE(ABORT, 'incident updated_at must be monotonic');
    END`,
  `CREATE TRIGGER timeline_occurred_at_monotonic
    BEFORE INSERT ON timeline_events
    WHEN EXISTS (
      SELECT 1 FROM timeline_events
      WHERE incident_id = NEW.incident_id AND occurred_at > NEW.occurred_at
    )
    BEGIN
      SELECT RAISE(ABORT, 'timeline occurred_at must be monotonic');
    END`,
] as const;
