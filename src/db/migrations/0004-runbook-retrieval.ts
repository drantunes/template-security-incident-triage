export const runbookRetrievalStatements = [
  `CREATE UNIQUE INDEX idx_workflow_runs_runbook_scope
    ON workflow_runs(tenant_id, incident_id, run_id)`,
  `CREATE TABLE runbook_activations (
    incident_kind TEXT PRIMARY KEY CHECK(incident_kind IN ('unauthorized_privilege_change','disallowed_country_login','unknown_device_login')),
    runbook_id TEXT NOT NULL,
    version TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    activated_at TEXT NOT NULL CHECK(activated_at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE(incident_kind, generation_id),
    FOREIGN KEY(generation_id, runbook_id, version, incident_kind)
      REFERENCES runbook_generations(generation_id, runbook_id, version, incident_kind) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE runbook_activation_events (
    incident_kind TEXT NOT NULL CHECK(incident_kind IN ('unauthorized_privilege_change','disallowed_country_login','unknown_device_login')),
    resulting_revision INTEGER NOT NULL CHECK(resulting_revision > 0),
    operation TEXT NOT NULL CHECK(operation IN ('activate','rollback')),
    from_generation_id TEXT,
    to_generation_id TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(incident_kind, resulting_revision),
    FOREIGN KEY(from_generation_id) REFERENCES runbook_generations(generation_id) ON DELETE RESTRICT,
    FOREIGN KEY(to_generation_id) REFERENCES runbook_generations(generation_id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE runbook_generation_cleanup_claims (
    generation_id TEXT PRIMARY KEY,
    index_name TEXT NOT NULL,
    expected_chunk_count INTEGER NOT NULL CHECK(expected_chunk_count >= 0),
    status TEXT NOT NULL CHECK(status IN ('claimed','deleted')),
    claimed_at TEXT NOT NULL CHECK(claimed_at GLOB '????-??-??T??:??:??.???Z'),
    completed_at TEXT CHECK(completed_at IS NULL OR completed_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK((status = 'claimed' AND completed_at IS NULL) OR (status = 'deleted' AND completed_at IS NOT NULL)),
    FOREIGN KEY(generation_id) REFERENCES runbook_generations(generation_id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE runbook_retrievals (
    retrieval_id TEXT PRIMARY KEY CHECK(length(trim(retrieval_id)) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    workflow_run_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    incident_kind TEXT NOT NULL CHECK(incident_kind IN ('unauthorized_privilege_change','disallowed_country_login','unknown_device_login')),
    runbook_id TEXT,
    version TEXT,
    generation_id TEXT,
    index_name TEXT,
    activation_revision INTEGER CHECK(activation_revision IS NULL OR activation_revision > 0),
    source_hash TEXT CHECK(source_hash IS NULL OR (length(source_hash) = 64 AND source_hash NOT GLOB '*[^0-9a-f]*')),
    generation_aggregate_hash TEXT CHECK(generation_aggregate_hash IS NULL OR (length(generation_aggregate_hash) = 64 AND generation_aggregate_hash NOT GLOB '*[^0-9a-f]*')),
    allowed_actions_json TEXT CHECK(allowed_actions_json IS NULL OR json_valid(allowed_actions_json)),
    citation TEXT,
    query_hash TEXT NOT NULL CHECK(length(query_hash) = 64 AND query_hash NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK(status IN ('in_progress','succeeded','manual_review','failed')),
    error_code TEXT,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt >= 0),
    lease_token TEXT CHECK(lease_token IS NULL OR length(lease_token) = 64),
    lease_expires_at TEXT CHECK(lease_expires_at IS NULL OR lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    threshold TEXT NOT NULL,
    top_k INTEGER NOT NULL CHECK(top_k BETWEEN 1 AND 20),
    policy_version INTEGER NOT NULL CHECK(policy_version = 1),
    selected_at TEXT NOT NULL CHECK(selected_at GLOB '????-??-??T??:??:??.???Z'),
    finished_at TEXT CHECK(finished_at IS NULL OR finished_at GLOB '????-??-??T??:??:??.???Z'),
    selection_integrity_hash TEXT CHECK(selection_integrity_hash IS NULL OR (length(selection_integrity_hash) = 64 AND selection_integrity_hash NOT GLOB '*[^0-9a-f]*')),
    aggregate_integrity_hash TEXT CHECK(aggregate_integrity_hash IS NULL OR (length(aggregate_integrity_hash) = 64 AND aggregate_integrity_hash NOT GLOB '*[^0-9a-f]*')),
    CHECK(finished_at IS NULL OR finished_at >= selected_at),
    CHECK((generation_id IS NULL AND runbook_id IS NULL AND version IS NULL AND index_name IS NULL
        AND activation_revision IS NULL AND source_hash IS NULL AND generation_aggregate_hash IS NULL
        AND allowed_actions_json IS NULL AND citation IS NULL AND selection_integrity_hash IS NULL)
      OR (generation_id IS NOT NULL AND runbook_id IS NOT NULL AND version IS NOT NULL
        AND index_name IS NOT NULL AND activation_revision IS NOT NULL AND source_hash IS NOT NULL
        AND generation_aggregate_hash IS NOT NULL AND allowed_actions_json IS NOT NULL AND citation IS NOT NULL
        AND selection_integrity_hash IS NOT NULL)),
    CHECK((status = 'in_progress' AND generation_id IS NOT NULL AND error_code IS NULL
        AND attempt > 0 AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
        AND finished_at IS NULL AND aggregate_integrity_hash IS NULL)
      OR (status = 'succeeded' AND generation_id IS NOT NULL AND error_code IS NULL
        AND attempt > 0 AND lease_token IS NULL AND lease_expires_at IS NULL
        AND finished_at IS NOT NULL AND aggregate_integrity_hash IS NOT NULL)
      OR (status IN ('manual_review','failed') AND error_code IS NOT NULL
        AND lease_token IS NULL AND lease_expires_at IS NULL
        AND ((generation_id IS NULL AND attempt = 0) OR (generation_id IS NOT NULL AND attempt > 0))
        AND finished_at IS NOT NULL AND aggregate_integrity_hash IS NOT NULL)),
    UNIQUE(tenant_id, incident_id, workflow_run_id, query_hash, policy_version),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, workflow_run_id)
      REFERENCES workflow_runs(tenant_id, incident_id, run_id) ON DELETE RESTRICT,
    FOREIGN KEY(generation_id, runbook_id, version, incident_kind)
      REFERENCES runbook_generations(generation_id, runbook_id, version, incident_kind) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE runbook_retrieval_chunks (
    retrieval_id TEXT NOT NULL,
    rank INTEGER NOT NULL CHECK(rank > 0),
    generation_id TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    vector_id TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK(length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
    metadata_hash TEXT NOT NULL CHECK(length(metadata_hash) = 64 AND metadata_hash NOT GLOB '*[^0-9a-f]*'),
    score_text TEXT NOT NULL,
    score REAL NOT NULL CHECK(score >= -1 AND score <= 1),
    section_ordinal INTEGER NOT NULL CHECK(section_ordinal BETWEEN 1 AND 9),
    chunk_ordinal INTEGER NOT NULL CHECK(chunk_ordinal >= 0),
    PRIMARY KEY(retrieval_id, rank),
    UNIQUE(retrieval_id, chunk_id),
    FOREIGN KEY(retrieval_id) REFERENCES runbook_retrievals(retrieval_id) ON DELETE RESTRICT,
    FOREIGN KEY(generation_id, chunk_id, vector_id)
      REFERENCES runbook_chunks(generation_id, chunk_id, vector_id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE INDEX idx_runbook_retrievals_incident ON runbook_retrievals(tenant_id, incident_id, selected_at)`,
  `CREATE INDEX idx_runbook_retrievals_generation ON runbook_retrievals(generation_id, selected_at)`,
  `CREATE INDEX idx_runbook_retrievals_in_progress ON runbook_retrievals(generation_id, status, lease_expires_at)`,
  `CREATE INDEX idx_runbook_activation_events_target ON runbook_activation_events(to_generation_id, resulting_revision)`,
  `CREATE INDEX idx_runbook_retrieval_chunks_chunk ON runbook_retrieval_chunks(generation_id, chunk_id)`,
] as const;
