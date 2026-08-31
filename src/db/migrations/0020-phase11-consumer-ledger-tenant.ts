/**
 * Rebuilds the consumer ledger with tenant-local identity. Legacy rows are
 * copied only when the workflow consumer's event id has one authoritative
 * outbox owner; all other rows remain in the explicitly withheld legacy table.
 */
export const phase11ConsumerLedgerTenantStatements = [
  `ALTER TABLE consumer_effect_ledger RENAME TO consumer_effect_ledger_legacy_withheld`,
  `DROP INDEX idx_consumer_effect_lease`,
  `CREATE TABLE consumer_effect_ledger (
    tenant_id TEXT NOT NULL CHECK(length(trim(tenant_id)) BETWEEN 1 AND 128),
    consumer_group TEXT NOT NULL CHECK(length(trim(consumer_group)) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL CHECK(length(trim(event_id)) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('processing','completed','dead_lettered')),
    attempt_count INTEGER NOT NULL CHECK(attempt_count > 0),
    fence_token TEXT NOT NULL CHECK(length(trim(fence_token)) BETWEEN 1 AND 128),
    lease_expires_at TEXT NOT NULL CHECK(lease_expires_at GLOB '????-??-??T??:??:??.???Z'),
    completed_at TEXT CHECK(completed_at IS NULL OR completed_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(tenant_id, consumer_group, event_id)
  ) STRICT`,
  `CREATE INDEX idx_consumer_effect_lease ON consumer_effect_ledger(tenant_id, status, lease_expires_at)`,
  `CREATE INDEX idx_consumer_effect_terminal ON consumer_effect_ledger(tenant_id, status, completed_at)`,
  `INSERT INTO consumer_effect_ledger(
    tenant_id, consumer_group, event_id, status, attempt_count, fence_token, lease_expires_at, completed_at
  ) SELECT o.tenant_id, legacy.consumer_group, legacy.event_id, legacy.status,
    legacy.attempt_count, legacy.fence_token, legacy.lease_expires_at, legacy.completed_at
    FROM consumer_effect_ledger_legacy_withheld legacy
    JOIN outbox_events o ON o.id = legacy.event_id
    WHERE legacy.consumer_group = 'security-workflow-starters'`,
  `DELETE FROM consumer_effect_ledger_legacy_withheld
    WHERE consumer_group = 'security-workflow-starters'
      AND EXISTS (SELECT 1 FROM outbox_events o WHERE o.id = event_id)`,
] as const;
