export const phase6ApprovalContainmentStatements = [
  `ALTER TABLE workflow_runs ADD COLUMN phase5_result_json TEXT
    CHECK(phase5_result_json IS NULL OR json_valid(phase5_result_json))`,
  `ALTER TABLE workflow_runs ADD COLUMN phase5_result_hash TEXT
    CHECK(phase5_result_hash IS NULL OR (length(phase5_result_hash) = 64 AND phase5_result_hash NOT GLOB '*[^0-9a-f]*'))`,
  `ALTER TABLE provider_deliveries ADD COLUMN projection_json TEXT
    CHECK(projection_json IS NULL OR json_valid(projection_json))`,
  `ALTER TABLE provider_deliveries ADD COLUMN workflow_run_id TEXT`,
  `ALTER TABLE provider_deliveries ADD COLUMN correlation_id TEXT`,
  `ALTER TABLE provider_deliveries ADD COLUMN provider_generation INTEGER
    CHECK(provider_generation IS NULL OR provider_generation > 0)`,
  `CREATE TRIGGER workflow_runs_phase5_result_immutable
    BEFORE UPDATE OF phase5_result_json, phase5_result_hash ON workflow_runs
    WHEN OLD.phase5_result_json IS NOT NULL AND (
      NEW.phase5_result_json IS NOT OLD.phase5_result_json
      OR NEW.phase5_result_hash IS NOT OLD.phase5_result_hash
    )
    BEGIN
      SELECT RAISE(ABORT, 'phase5 result is immutable');
    END`,
  `ALTER TABLE approvals ADD COLUMN workflow_run_id TEXT`,
  `ALTER TABLE approvals ADD COLUMN decision_fingerprint TEXT
    CHECK(decision_fingerprint IS NULL OR (length(decision_fingerprint) = 64 AND decision_fingerprint NOT GLOB '*[^0-9a-f]*'))`,
  `ALTER TABLE approvals ADD COLUMN expiry_resumed_at TEXT
    CHECK(expiry_resumed_at IS NULL OR expiry_resumed_at GLOB '????-??-??T??:??:??.???Z')`,
  `CREATE INDEX idx_approvals_tenant_incident_run
    ON approvals(tenant_id, incident_id, workflow_run_id)`,
  `CREATE UNIQUE INDEX idx_approvals_phase6_token_binding
    ON approvals(tenant_id, incident_id, workflow_run_id, id, decision,
      decision_fingerprint, expires_at)`,
  `CREATE UNIQUE INDEX idx_approvals_phase6_plan_binding
    ON approvals(tenant_id, incident_id, plan_id, id)`,
  `CREATE UNIQUE INDEX idx_containment_actions_phase6_binding
    ON containment_actions(tenant_id, incident_id, plan_id, action_id, idempotency_key)`,
  `CREATE TRIGGER approvals_phase6_run_required
    BEFORE INSERT ON approvals
    WHEN NEW.workflow_run_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM workflow_runs w
      WHERE w.tenant_id = NEW.tenant_id
        AND w.incident_id = NEW.incident_id
        AND w.run_id = NEW.workflow_run_id
    )
    BEGIN
      SELECT RAISE(ABORT, 'approval workflow run binding required');
    END`,
  `CREATE TRIGGER approvals_phase6_run_immutable
    BEFORE UPDATE OF workflow_run_id ON approvals
    WHEN NEW.workflow_run_id IS NOT OLD.workflow_run_id
    BEGIN
      SELECT RAISE(ABORT, 'approval workflow run binding is immutable');
    END`,
  `CREATE TRIGGER approvals_phase6_expiry_resume_monotonic
    BEFORE UPDATE OF expiry_resumed_at ON approvals
    WHEN OLD.expiry_resumed_at IS NOT NULL OR NEW.expiry_resumed_at IS NULL
    BEGIN
      SELECT RAISE(ABORT, 'approval expiry resume marker is monotonic');
    END`,
  `CREATE TABLE approval_resume_tokens (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    workflow_run_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
    decision_fingerprint TEXT NOT NULL CHECK(length(decision_fingerprint) = 64 AND decision_fingerprint NOT GLOB '*[^0-9a-f]*'),
    digest_version INTEGER NOT NULL CHECK(digest_version = 1),
    token_digest TEXT NOT NULL UNIQUE CHECK(length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'),
    issued_at TEXT NOT NULL CHECK(issued_at GLOB '????-??-??T??:??:??.???Z'),
    expires_at TEXT NOT NULL CHECK(expires_at GLOB '????-??-??T??:??:??.???Z'),
    consumed_at TEXT CHECK(consumed_at IS NULL OR consumed_at GLOB '????-??-??T??:??:??.???Z'),
    resumed_at TEXT CHECK(resumed_at IS NULL OR resumed_at GLOB '????-??-??T??:??:??.???Z'),
    CHECK(expires_at > issued_at),
    CHECK(consumed_at IS NULL OR consumed_at >= issued_at),
    CHECK(resumed_at IS NULL OR (consumed_at IS NOT NULL AND resumed_at >= consumed_at)),
    UNIQUE(tenant_id, incident_id, workflow_run_id, approval_id, decision),
    FOREIGN KEY(tenant_id, incident_id, workflow_run_id, approval_id, decision,
      decision_fingerprint, expires_at)
      REFERENCES approvals(tenant_id, incident_id, workflow_run_id, id, decision,
        decision_fingerprint, expires_at) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE INDEX idx_resume_tokens_binding
    ON approval_resume_tokens(tenant_id, incident_id, workflow_run_id, approval_id, consumed_at)`,
  `CREATE TRIGGER approval_resume_tokens_no_delete
    BEFORE DELETE ON approval_resume_tokens
    BEGIN
      SELECT RAISE(ABORT, 'resume token ledger is append-only');
    END`,
  `CREATE TRIGGER approval_resume_tokens_immutable
    BEFORE UPDATE ON approval_resume_tokens
    WHEN NEW.id IS NOT OLD.id
      OR NEW.tenant_id IS NOT OLD.tenant_id
      OR NEW.incident_id IS NOT OLD.incident_id
      OR NEW.workflow_run_id IS NOT OLD.workflow_run_id
      OR NEW.approval_id IS NOT OLD.approval_id
      OR NEW.decision IS NOT OLD.decision
      OR NEW.decision_fingerprint IS NOT OLD.decision_fingerprint
      OR NEW.digest_version IS NOT OLD.digest_version
      OR NEW.token_digest IS NOT OLD.token_digest
      OR NEW.issued_at IS NOT OLD.issued_at
      OR NEW.expires_at IS NOT OLD.expires_at
      OR (OLD.consumed_at IS NULL AND NEW.consumed_at IS NULL)
      OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NOT OLD.consumed_at)
      OR (OLD.resumed_at IS NOT NULL AND NEW.resumed_at IS NOT OLD.resumed_at)
      OR (OLD.resumed_at IS NULL AND NEW.resumed_at IS NULL AND OLD.consumed_at IS NOT NULL)
    BEGIN
      SELECT RAISE(ABORT, 'resume token record is immutable');
    END`,
  `CREATE TABLE containment_action_attempts (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    owner_id TEXT NOT NULL CHECK(length(trim(owner_id)) BETWEEN 1 AND 128),
    fence_token TEXT NOT NULL UNIQUE CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('executing','completed','blocked','failed','timed_out')),
    started_at TEXT NOT NULL CHECK(started_at GLOB '????-??-??T??:??:??.???Z'),
    finished_at TEXT CHECK(finished_at IS NULL OR finished_at GLOB '????-??-??T??:??:??.???Z'),
    lease_expires_at TEXT NOT NULL CHECK(lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    error_code TEXT CHECK(error_code IS NULL OR error_code IN ('ACTION_BLOCKED','PRECONDITION_FAILED','RATE_LIMITED','PROVIDER_FAILED','PROVIDER_TIMEOUT','VERIFICATION_FAILED')),
    provider_ref TEXT,
    verification TEXT NOT NULL CHECK(verification IN ('not_run','verified','not_verified')),
    CHECK((status = 'executing' AND finished_at IS NULL) OR (status != 'executing' AND finished_at IS NOT NULL)),
    UNIQUE(tenant_id, plan_id, action_id, attempt),
    UNIQUE(tenant_id, idempotency_key, attempt),
    FOREIGN KEY(tenant_id, incident_id, plan_id, approval_id)
      REFERENCES approvals(tenant_id, incident_id, plan_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, plan_id, action_id, idempotency_key)
      REFERENCES containment_actions(tenant_id, incident_id, plan_id, action_id, idempotency_key)
      ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, plan_id) REFERENCES containment_plans(tenant_id, incident_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE INDEX idx_action_attempts_current
    ON containment_action_attempts(tenant_id, plan_id, action_id, attempt DESC)`,
  `CREATE TRIGGER containment_action_attempts_no_delete
    BEFORE DELETE ON containment_action_attempts
    BEGIN
      SELECT RAISE(ABORT, 'containment attempt ledger is append-only');
    END`,
  `CREATE TRIGGER containment_action_attempts_closed_immutable
    BEFORE UPDATE ON containment_action_attempts
    WHEN OLD.status != 'executing'
      OR NEW.id IS NOT OLD.id
      OR NEW.tenant_id IS NOT OLD.tenant_id
      OR NEW.incident_id IS NOT OLD.incident_id
      OR NEW.plan_id IS NOT OLD.plan_id
      OR NEW.approval_id IS NOT OLD.approval_id
      OR NEW.action_id IS NOT OLD.action_id
      OR NEW.idempotency_key IS NOT OLD.idempotency_key
      OR NEW.attempt IS NOT OLD.attempt
      OR NEW.owner_id IS NOT OLD.owner_id
      OR NEW.fence_token IS NOT OLD.fence_token
      OR NEW.started_at IS NOT OLD.started_at
      OR NEW.lease_expires_at IS NOT OLD.lease_expires_at
      OR NEW.status = 'executing'
      OR NEW.finished_at IS NULL
    BEGIN
      SELECT RAISE(ABORT, 'containment attempt is immutable');
    END`,
  `CREATE TRIGGER containment_actions_status_guard_insert
    BEFORE INSERT ON containment_actions
    WHEN NEW.status NOT IN ('pending','executing','completed','blocked','failed','timed_out')
    BEGIN
      SELECT RAISE(ABORT, 'invalid containment action status');
    END`,
  `CREATE TRIGGER containment_actions_status_guard_update
    BEFORE UPDATE OF status ON containment_actions
    WHEN NEW.status NOT IN ('pending','executing','completed','blocked','failed','timed_out')
    BEGIN
      SELECT RAISE(ABORT, 'invalid containment action status');
    END`,
  `CREATE TABLE mock_incident_provider_effects (
    idempotency_key TEXT PRIMARY KEY CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 256),
    operation TEXT NOT NULL CHECK(operation IN ('create','update')),
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    projection_json TEXT NOT NULL CHECK(json_valid(projection_json)),
    external_ref TEXT NOT NULL CHECK(length(external_ref) = 30
      AND substr(external_ref, 1, 14) = 'mock-incident-'
      AND substr(external_ref, 15) NOT GLOB '*[^0-9a-f]*'),
    UNIQUE(tenant_id, incident_id, idempotency_key),
    UNIQUE(tenant_id, incident_id, generation),
    FOREIGN KEY(tenant_id, incident_id) REFERENCES incidents(tenant_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TRIGGER mock_incident_provider_effects_no_update
    BEFORE UPDATE ON mock_incident_provider_effects
    BEGIN SELECT RAISE(ABORT, 'mock provider effect is append-only'); END`,
  `CREATE TRIGGER mock_incident_provider_effects_no_delete
    BEFORE DELETE ON mock_incident_provider_effects
    BEGIN SELECT RAISE(ABORT, 'mock provider effect is append-only'); END`,
  `CREATE TABLE mock_containment_effects (
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK(action_type IN ('revoke_session','restore_previous_role','mark_device_for_review','require_reauthentication')),
    target_id TEXT NOT NULL CHECK(length(trim(target_id)) BETWEEN 1 AND 128),
    input_json TEXT NOT NULL CHECK(json_valid(input_json)),
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    fence_token TEXT NOT NULL CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    provider_ref TEXT NOT NULL CHECK(length(trim(provider_ref)) BETWEEN 1 AND 256),
    applied_at TEXT NOT NULL CHECK(applied_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(tenant_id, incident_id, plan_id, action_id),
    FOREIGN KEY(plan_id, action_id) REFERENCES containment_actions(plan_id, action_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, incident_id, plan_id)
      REFERENCES containment_plans(tenant_id, incident_id, id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TRIGGER mock_containment_effects_no_update
    BEFORE UPDATE ON mock_containment_effects
    BEGIN SELECT RAISE(ABORT, 'mock containment effect is append-only'); END`,
  `CREATE TRIGGER mock_containment_effects_no_delete
    BEFORE DELETE ON mock_containment_effects
    BEGIN SELECT RAISE(ABORT, 'mock containment effect is append-only'); END`,
  `CREATE TABLE containment_gateway_audit (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    claimed_tenant_id TEXT NOT NULL CHECK(length(trim(claimed_tenant_id)) BETWEEN 1 AND 128),
    claimed_incident_id TEXT NOT NULL CHECK(length(trim(claimed_incident_id)) BETWEEN 1 AND 128),
    claimed_plan_id TEXT NOT NULL CHECK(length(trim(claimed_plan_id)) BETWEEN 1 AND 128),
    claimed_approval_id TEXT NOT NULL CHECK(length(trim(claimed_approval_id)) BETWEEN 1 AND 128),
    claimed_action_id TEXT NOT NULL CHECK(length(trim(claimed_action_id)) BETWEEN 1 AND 128),
    outcome TEXT NOT NULL CHECK(outcome IN ('invalid','blocked','expired','rate_limited','replayed')),
    reason_code TEXT NOT NULL CHECK(reason_code IN ('BINDING_INVALID','MODE_BLOCKED','APPROVAL_EXPIRED','PREDECESSOR_INCOMPLETE','RATE_LIMITED','ALREADY_VERIFIED','ACTION_IN_PROGRESS')),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z')
  ) STRICT`,
  `CREATE INDEX idx_containment_gateway_audit_scope
    ON containment_gateway_audit(claimed_tenant_id, claimed_incident_id, occurred_at)`,
  `CREATE TRIGGER containment_gateway_audit_no_update
    BEFORE UPDATE ON containment_gateway_audit
    BEGIN
      SELECT RAISE(ABORT, 'gateway audit is append-only');
    END`,
  `CREATE TRIGGER containment_gateway_audit_no_delete
    BEFORE DELETE ON containment_gateway_audit
    BEGIN
      SELECT RAISE(ABORT, 'gateway audit is append-only');
    END`,
  `CREATE TABLE approval_decision_audit (
    id TEXT PRIMARY KEY CHECK(length(trim(id)) BETWEEN 1 AND 128),
    claimed_tenant_id TEXT,
    claimed_incident_id TEXT NOT NULL CHECK(length(trim(claimed_incident_id)) BETWEEN 1 AND 128),
    claimed_approval_id TEXT NOT NULL CHECK(length(trim(claimed_approval_id)) BETWEEN 1 AND 128),
    outcome TEXT NOT NULL CHECK(outcome IN ('invalid','blocked','expired','replayed')),
    reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) BETWEEN 1 AND 64),
    occurred_at TEXT NOT NULL CHECK(occurred_at GLOB '????-??-??T??:??:??.???Z')
  ) STRICT`,
  `CREATE INDEX idx_approval_decision_audit_scope
    ON approval_decision_audit(claimed_tenant_id, claimed_incident_id, occurred_at)`,
  `CREATE TRIGGER approval_decision_audit_no_update
    BEFORE UPDATE ON approval_decision_audit
    BEGIN SELECT RAISE(ABORT, 'decision audit is append-only'); END`,
  `CREATE TRIGGER approval_decision_audit_no_delete
    BEFORE DELETE ON approval_decision_audit
    BEGIN SELECT RAISE(ABORT, 'decision audit is append-only'); END`,
] as const;
