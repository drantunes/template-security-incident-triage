/**
 * Phase 8 durable boundaries. These tables contain only opaque identifiers or
 * keyed network cache handles; raw provider payloads and IP addresses never enter the
 * operational store.
 */
export const phase8ProviderDurabilityStatements = [
  // Provider event identifiers are delivery identities, not tenant-local
  // names. Refuse a replay that tries to reuse one under a different source.
  `CREATE UNIQUE INDEX idx_alerts_source_event_id_global ON alerts(source_event_id)`,
  // Earlier containment rows predate target persistence. They remain
  // non-authoritative for real identity effects; new plans persist target.
  `ALTER TABLE containment_actions ADD COLUMN target_id TEXT`,
  `CREATE TABLE geoip_cache_entries (
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK(policy_version IN (1,2)),
    key_version TEXT NOT NULL
      CHECK(length(trim(key_version)) BETWEEN 1 AND 64
        AND key_version NOT GLOB '*[^a-zA-Z0-9._-]*'),
    ip_hash TEXT NOT NULL CHECK(length(ip_hash) = 64 AND ip_hash NOT GLOB '*[^0-9a-f]*'),
    result_json TEXT NOT NULL CHECK(json_valid(result_json)),
    observed_at TEXT NOT NULL CHECK(observed_at GLOB '????-??-??T??:??:??.???Z'),
    expires_at TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??.???Z'),
    purge_after TEXT NOT NULL CHECK(purge_after GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(tenant_id, policy_version, key_version, ip_hash),
    CHECK(expires_at > observed_at), CHECK(purge_after > expires_at)
  ) STRICT`,
  `CREATE INDEX idx_geoip_cache_expiry ON geoip_cache_entries(expires_at, purge_after)`,
  `CREATE TABLE geoip_cache_leases (
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK(policy_version IN (1,2)),
    key_version TEXT NOT NULL
      CHECK(length(trim(key_version)) BETWEEN 1 AND 64
        AND key_version NOT GLOB '*[^a-zA-Z0-9._-]*'),
    ip_hash TEXT NOT NULL CHECK(length(ip_hash) = 64 AND ip_hash NOT GLOB '*[^0-9a-f]*'),
    fence_token TEXT NOT NULL CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    lease_expires_at TEXT NOT NULL CHECK(lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(tenant_id, policy_version, key_version, ip_hash)
  ) STRICT`,
  `CREATE INDEX idx_geoip_cache_lease_expiry ON geoip_cache_leases(lease_expires_at)`,
  `CREATE TABLE provider_effect_ledger (
    provider TEXT NOT NULL CHECK(provider IN ('linear','workos')),
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 256),
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    incident_id TEXT NOT NULL CHECK(length(trim(incident_id)) BETWEEN 1 AND 128),
    operation TEXT NOT NULL CHECK(length(trim(operation)) BETWEEN 1 AND 64),
    plan_id TEXT NOT NULL CHECK(length(trim(plan_id)) BETWEEN 1 AND 128),
    action_id TEXT NOT NULL CHECK(length(trim(action_id)) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK(length(trim(target_id)) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('claimed','succeeded','uncertain','failed')),
    external_ref TEXT,
    fence_token TEXT,
    claimed_at TEXT NOT NULL CHECK(claimed_at GLOB '????-??-??T??:??:??.???Z'),
    completed_at TEXT CHECK(completed_at IS NULL OR completed_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(provider, idempotency_key),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE INDEX idx_provider_effect_reconcile ON provider_effect_ledger(provider, status, claimed_at)`,
  // One monotonic authority per external projection.  Provider-delivery rows
  // are operation-specific; this ledger prevents a later retry of another
  // operation from regressing an already delivered Linear generation.
  `CREATE TABLE provider_incident_generations (
    provider TEXT NOT NULL CHECK(provider IN ('linear','mock-incident')),
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    incident_id TEXT NOT NULL CHECK(length(trim(incident_id)) BETWEEN 1 AND 128),
    generation INTEGER NOT NULL CHECK(generation > 0),
    fence_token TEXT NOT NULL CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('active','terminal','reconciled')),
    claimed_at TEXT NOT NULL CHECK(claimed_at GLOB '????-??-??T??:??:??.???Z'),
    lease_expires_at TEXT NOT NULL CHECK(lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    external_ref TEXT,
    PRIMARY KEY(provider, tenant_id, incident_id),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE INDEX idx_provider_incident_generations_fence
    ON provider_incident_generations(provider, tenant_id, incident_id, generation)`,
  `CREATE INDEX idx_provider_incident_generations_lease
    ON provider_incident_generations(status, lease_expires_at)`,
  `CREATE TABLE consumer_effect_ledger (
    consumer_group TEXT NOT NULL CHECK(length(trim(consumer_group)) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL CHECK(length(trim(event_id)) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('processing','completed','dead_lettered')),
    attempt_count INTEGER NOT NULL CHECK(attempt_count > 0),
    fence_token TEXT NOT NULL CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    lease_expires_at TEXT NOT NULL CHECK(lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    completed_at TEXT CHECK(completed_at IS NULL OR completed_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(consumer_group, event_id)
  ) STRICT`,
  `CREATE INDEX idx_consumer_effect_lease ON consumer_effect_ledger(status, lease_expires_at)`,
  // Local, authoritative authorization only. This is deliberately separate
  // from a WorkOS webhook so an external payload can never self-approve a
  // privilege change used by policy/claims.
  `CREATE TABLE identity_role_change_authorizations (
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    subject_id TEXT NOT NULL CHECK(length(trim(subject_id)) BETWEEN 1 AND 128),
    source_event_id TEXT NOT NULL CHECK(length(trim(source_event_id)) BETWEEN 1 AND 128),
    actor_id TEXT NOT NULL CHECK(length(trim(actor_id)) BETWEEN 1 AND 128),
    previous_role TEXT NOT NULL CHECK(previous_role IN ('admin','member','viewer')),
    current_role TEXT NOT NULL CHECK(current_role IN ('admin','member','viewer')),
    approved INTEGER NOT NULL CHECK(approved IN (0,1)),
    recorded_at TEXT NOT NULL CHECK(recorded_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(tenant_id, subject_id, source_event_id)
  ) STRICT`,
  `CREATE TABLE redis_decode_failures (
    stream_id TEXT NOT NULL CHECK(length(trim(stream_id)) BETWEEN 1 AND 128),
    topic TEXT NOT NULL CHECK(length(trim(topic)) BETWEEN 1 AND 256),
    consumer_group TEXT NOT NULL CHECK(length(trim(consumer_group)) BETWEEN 1 AND 128),
    consumer_name TEXT NOT NULL CHECK(length(trim(consumer_name)) BETWEEN 1 AND 256),
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
    payload_size INTEGER NOT NULL CHECK(payload_size >= 0 AND payload_size <= 262144),
    error_code TEXT NOT NULL CHECK(error_code = 'EVENT_INVALID'),
    created_at TEXT NOT NULL CHECK(created_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(stream_id, consumer_group)
  ) STRICT`,
  // 0007 has not shipped. Bind every newly captured restore snapshot to the
  // exact incident that owns the authoritative alert. The guard is a trigger
  // rather than a table rebuild so an upgrade from 0001–0006 preserves the
  // pre-existing operational table without copying or weakening it.
  `ALTER TABLE identity_snapshots ADD COLUMN incident_id TEXT`,
  `CREATE TRIGGER identity_snapshots_incident_binding_insert
    BEFORE INSERT ON identity_snapshots
    FOR EACH ROW WHEN NEW.incident_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM incidents
      WHERE id = NEW.incident_id AND tenant_id = NEW.tenant_id
        AND subject_id = NEW.subject_id
    )
    BEGIN SELECT RAISE(ABORT, 'identity snapshot incident binding invalid'); END`,
  `CREATE TRIGGER identity_snapshots_incident_binding_update
    BEFORE UPDATE OF incident_id, tenant_id, subject_id ON identity_snapshots
    FOR EACH ROW WHEN NEW.incident_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM incidents
      WHERE id = NEW.incident_id AND tenant_id = NEW.tenant_id
        AND subject_id = NEW.subject_id
    )
    BEGIN SELECT RAISE(ABORT, 'identity snapshot incident binding invalid'); END`,
  `CREATE UNIQUE INDEX idx_identity_snapshots_incident_source
    ON identity_snapshots(tenant_id, incident_id, subject_id, source_event_id)`,
  `CREATE INDEX idx_identity_snapshots_restore_binding
    ON identity_snapshots(tenant_id, incident_id, subject_id, captured_at DESC)`,
  // F8 has not shipped a migration yet, so the WorkOS baseline belongs to
  // the same provider-durability delta rather than a new public version.
  `CREATE TABLE workos_observed_memberships (
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    observed_role TEXT NOT NULL CHECK(observed_role IN ('admin','member','viewer')),
    observed_status TEXT NOT NULL DEFAULT 'active'
      CHECK(observed_status IN ('active','inactive','pending')),
    observed_state_hash TEXT NOT NULL DEFAULT '${"0".repeat(64)}'
      CHECK(length(observed_state_hash) = 64 AND observed_state_hash NOT GLOB '*[^0-9a-f]*'),
    incident_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    observed_at TEXT NOT NULL CHECK(observed_at GLOB '????-??-??T??:??:??.???Z'),
    version INTEGER NOT NULL CHECK(version > 0),
    PRIMARY KEY(tenant_id, subject_id, membership_id)
  ) STRICT`,
  `CREATE INDEX idx_workos_observed_memberships_subject
    ON workos_observed_memberships(tenant_id, subject_id, observed_at DESC)`,
  // Session lifecycle events use the same ordering rule as memberships.  The
  // canonical state hash makes equal ordering positions idempotent while
  // refusing contradictory provider payloads.
  `CREATE TABLE workos_observed_sessions (
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    observed_status TEXT NOT NULL CHECK(observed_status IN ('active','revoked','expired')),
    observed_state_hash TEXT NOT NULL
      CHECK(length(observed_state_hash) = 64 AND observed_state_hash NOT GLOB '*[^0-9a-f]*'),
    incident_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    observed_at TEXT NOT NULL CHECK(observed_at GLOB '????-??-??T??:??:??.???Z'),
    version INTEGER NOT NULL CHECK(version > 0),
    PRIMARY KEY(tenant_id, subject_id, session_id)
  ) STRICT`,
  `CREATE INDEX idx_workos_observed_sessions_subject
    ON workos_observed_sessions(tenant_id, subject_id, observed_at DESC)`,
  // An object may later advance to a newer state. Keep only canonical hashes
  // for prior timestamp positions so delayed exact retries still converge.
  `CREATE TABLE workos_observed_positions (
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('membership','session')),
    object_id TEXT NOT NULL,
    observed_at TEXT NOT NULL CHECK(observed_at GLOB '????-??-??T??:??:??.???Z'),
    state_hash TEXT NOT NULL
      CHECK(length(state_hash) = 64 AND state_hash NOT GLOB '*[^0-9a-f]*'),
    incident_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, subject_id, object_type, object_id, observed_at)
  ) STRICT`,
  `ALTER TABLE approvals ADD COLUMN decision_provenance TEXT NOT NULL DEFAULT 'mock'
    CHECK(decision_provenance IN ('mock','dashboard'))`,
] as const;
