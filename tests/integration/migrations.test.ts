import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { DuckDbAnalyticsStore } from "../../src/analytics/duckdb-analytics-store.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import {
  migrationChecksum,
  migrations,
} from "../../src/db/migrations/index.js";
import { phase11CanonicalTenantReconciliationIntegrity } from "../../src/db/migrations/0023-phase11-canonical-tenant-reconciliation.js";
import { phase11CanonicalTenantReconciliationStatements } from "../../src/db/migrations/0023-phase11-canonical-tenant-reconciliation.js";
import { exportAnalyticsSince } from "../../src/analytics/exporter.js";
import { isCanonicalTenantId } from "../../src/schemas/common.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("SOC migrations", () => {
  it("creates the operational and runbook tables, constraints and indexes from an empty database", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, {
        appliedAt: "2026-08-27T12:00:00.000Z",
      });
      const tables = await store.execute({
        sql: `SELECT name FROM sqlite_master
          WHERE type = 'table' AND (name LIKE 'soc_%' OR name IN (
            'incidents','alerts','evidence_items','workflow_runs','containment_plans',
            'containment_actions','approvals','timeline_events','authorized_devices',
            'identity_snapshots','provider_deliveries','outbox_events','dead_letter_events',
            'runbook_versions','runbook_generations','runbook_chunks','runbook_activations',
            'runbook_activation_events','runbook_generation_cleanup_claims',
            'runbook_retrievals','runbook_retrieval_chunks','approval_resume_tokens',
            'containment_action_attempts','containment_gateway_audit',
            'approval_decision_audit','mock_incident_provider_effects',
            'mock_containment_effects','geoip_cache_entries','geoip_cache_leases','provider_effect_ledger',
            'consumer_effect_ledger','consumer_effect_ledger_legacy_withheld',
            'retention_tombstone_claims_legacy_withheld',
            'workos_observed_memberships','workos_observed_sessions',
            'workos_observed_positions','eval_results','analytics_export_events',
            'retention_audit_events','retention_tombstones','retention_tombstone_claims',
            'retention_source_cursors'
          )) ORDER BY name`,
      });
      expect(tables.rows).toHaveLength(43);
      expect(tables.rows.map((row) => row.name)).toContain(
        "soc_schema_migrations",
      );
      expect(tables.rows.map((row) => row.name)).toContain(
        "workos_observed_memberships",
      );
      expect(tables.rows.map((row) => row.name)).toContain(
        "workos_observed_sessions",
      );
      expect(tables.rows.map((row) => row.name)).toContain(
        "workos_observed_positions",
      );
      await expect(
        store.execute({
          sql: "SELECT tenant_id FROM retention_audit_events WHERE 1 = 0",
        }),
      ).resolves.toBeDefined();
      await expect(
        store.execute({
          sql: "SELECT next_source FROM retention_source_cursors WHERE 1 = 0",
        }),
      ).resolves.toBeDefined();

      const indexes = await store.execute({
        sql: "SELECT count(*) AS count FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
      });
      expect(Number(indexes.rows[0]?.count)).toBe(55);
      const tokenForeignKeys = await store.execute({
        sql: "PRAGMA foreign_key_list(approval_resume_tokens)",
      });
      expect(
        tokenForeignKeys.rows.filter((row) => row.table === "approvals"),
      ).toHaveLength(7);
      const attemptForeignKeys = await store.execute({
        sql: "PRAGMA foreign_key_list(containment_action_attempts)",
      });
      expect(
        attemptForeignKeys.rows.filter(
          (row) => row.table === "containment_actions",
        ),
      ).toHaveLength(5);
      expect(
        attemptForeignKeys.rows.filter((row) => row.table === "approvals"),
      ).toHaveLength(4);

      await expect(
        store.execute({
          sql: `INSERT INTO incidents(
            id, tenant_id, kind, subject_id, status, created_at, updated_at
          ) VALUES ('bad', 'tenant', 'unknown_device_login', 'subject', 'invalid',
            '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
    } finally {
      store.close();
    }
  });

  it("upgrades 0001–0006 through the Phase 8 dedupe correction, then reapplies safely", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    let store = database.createStore();
    await migrateOperationalStore(store, { targetVersion: 1 });
    await migrateOperationalStore(store, { targetVersion: 2 });
    await store.execute({
      sql: `INSERT INTO incidents(
        id, tenant_id, kind, subject_id, status, created_at, updated_at
      ) VALUES ('incident-preserved', 'tenant-1', 'unknown_device_login', 'subject-1',
        'received', '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
    });
    await migrateOperationalStore(store, { targetVersion: 6 });
    await migrateOperationalStore(store, { targetVersion: 7 });
    await migrateOperationalStore(store, { targetVersion: 8 });
    await migrateOperationalStore(store, { targetVersion: 8 });
    store.close();

    store = database.createStore();
    try {
      await migrateOperationalStore(store);
      const data = await store.execute({
        sql: "SELECT id FROM incidents WHERE tenant_id = ? AND id = ?",
        args: ["tenant-1", "incident-preserved"],
      });
      expect(data.rows).toEqual([{ id: "incident-preserved" }]);
      const ledger = await store.execute({
        sql: "SELECT version FROM soc_schema_migrations ORDER BY version",
      });
      expect(ledger.rows).toEqual([
        { version: 1 },
        { version: 2 },
        { version: 3 },
        { version: 4 },
        { version: 5 },
        { version: 6 },
        { version: 7 },
        { version: 8 },
        { version: 9 },
        { version: 10 },
        { version: 11 },
        { version: 12 },
        { version: 13 },
        { version: 14 },
        { version: 15 },
        { version: 16 },
        { version: 17 },
        { version: 18 },
        { version: 19 },
        { version: 20 },
        { version: 21 },
        { version: 22 },
        { version: 23 },
        { version: 24 },
        { version: 25 },
      ]);
      await expect(
        store.execute({
          sql: `SELECT decision_provenance FROM approvals WHERE 1 = 0`,
        }),
      ).resolves.toBeDefined();
    } finally {
      store.close();
    }
  });

  it("migrates only legacy consumer effects with an unambiguous outbox tenant", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, { targetVersion: 19 });
      const timestamp = "2026-08-27T12:00:00.000Z";
      await store.execute({
        sql: `INSERT INTO incidents(id, tenant_id, kind, subject_id, status, created_at, updated_at)
          VALUES ('incident-consumer', 'tenant-a', 'unknown_device_login', 'subject', 'received', ?, ?)`,
        args: [timestamp, timestamp],
      });
      await store.execute({
        sql: `INSERT INTO outbox_events(
          id, type, run_id, incident_id, tenant_id, schema_version, correlation_id, payload_json, occurred_at, available_at
        ) VALUES ('outbox-consumer', 'security.incident.updated', 'run', 'incident-consumer', 'tenant-a', 1, 'correlation', '{}', ?, ?)`,
        args: [timestamp, timestamp],
      });
      await store.execute({
        sql: `INSERT INTO consumer_effect_ledger(
          consumer_group, event_id, status, attempt_count, fence_token, lease_expires_at, completed_at
        ) VALUES
          ('security-workflow-starters', 'outbox-consumer', 'completed', 1, 'fence-owned', ?, ?),
          ('phase9-device-nonce', 'opaque-legacy', 'completed', 1, 'fence-withheld', ?, ?)`,
        args: [timestamp, timestamp, timestamp, timestamp],
      });
      await migrateOperationalStore(store);
      await expect(
        store.execute({
          sql: "SELECT tenant_id, event_id FROM consumer_effect_ledger",
        }),
      ).resolves.toMatchObject({
        rows: [{ tenant_id: "tenant-a", event_id: "outbox-consumer" }],
      });
      await expect(
        store.execute({
          sql: "SELECT consumer_group, event_id FROM consumer_effect_ledger_legacy_withheld",
        }),
      ).resolves.toMatchObject({
        rows: [
          { consumer_group: "phase9-device-nonce", event_id: "opaque-legacy" },
        ],
      });
      await migrateOperationalStore(store);
    } finally {
      store.close();
    }
  });

  it("preserves only canonical legacy retention tenants and withholds invalid identities", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, { targetVersion: 21 });
      const timestamp = "2026-08-27T12:00:00.000Z";
      await store.execute({
        sql: "INSERT INTO retention_source_cursors(tenant_id, next_source) VALUES ('tenant-a', 1), (' tenant-a ', 2)",
      });
      await store.execute({
        sql: `INSERT INTO retention_tombstone_claims(
          source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
        ) VALUES
          ('timeline_events', '["valid"]', 'tenant-a', 'three-hundred-sixty-five-day', 'retained-authority', ?, ?, 'sweep-valid'),
          ('timeline_events', '["withheld"]', ' tenant-a ', 'three-hundred-sixty-five-day', 'retained-authority', ?, ?, 'sweep-withheld')`,
        args: [timestamp, timestamp, timestamp, timestamp],
      });
      await migrateOperationalStore(store);
      await expect(
        store.execute({
          sql: "SELECT tenant_id FROM retention_source_cursors ORDER BY tenant_id",
        }),
      ).resolves.toMatchObject({ rows: [{ tenant_id: "tenant-a" }] });
      await expect(
        store.execute({
          sql: "SELECT tenant_id FROM retention_tombstone_claims ORDER BY tenant_id",
        }),
      ).resolves.toMatchObject({ rows: [{ tenant_id: "tenant-a" }] });
      await expect(
        store.execute({
          sql: "SELECT count(*) AS count FROM retention_tombstone_claims_v21_legacy_withheld WHERE tenant_id = ' tenant-a '",
        }),
      ).resolves.toMatchObject({ rows: [{ count: 1 }] });
    } finally {
      store.close();
    }
  });

  it("reconciles v22 whitespace tenants through the shared Unicode boundary", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, { targetVersion: 22 });
      const timestamp = "2026-08-27T12:00:00.000Z";
      const emoji128 = "😀".repeat(128);
      await store.execute({
        sql: `INSERT INTO retention_source_cursors(tenant_id, next_source) VALUES (?, 1), (?, 2), (?, 3)`,
        args: ["\ttenant-tab", "\u00a0tenant-nbsp", emoji128],
      });
      await store.execute({
        sql: `INSERT INTO retention_tombstone_claims(
          source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
        ) VALUES ('timeline_events', '["tab"]', ?, 'three-hundred-sixty-five-day', 'retained-authority', ?, ?, 'sweep-tab')`,
        args: ["\ttenant-tab", timestamp, timestamp],
      });
      await migrateOperationalStore(store);
      await expect(
        store.execute({
          sql: "SELECT tenant_id FROM retention_source_cursors ORDER BY next_source",
        }),
      ).resolves.toMatchObject({ rows: [{ tenant_id: emoji128 }] });
      await expect(
        store.execute({
          sql: "SELECT count(*) AS count FROM retention_tenant_quarantine",
        }),
      ).resolves.toMatchObject({ rows: [{ count: 3 }] });
      await expect(
        store.execute({
          sql: "SELECT count(*) AS count FROM retention_tombstone_claims WHERE tenant_id = ?",
          args: ["\ttenant-tab"],
        }),
      ).resolves.toMatchObject({ rows: [{ count: 0 }] });
    } finally {
      store.close();
    }
  });

  it("upgrades Phase 8 authority without inventing provider time and reconstructs terminal approvals", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, { targetVersion: 8 });
      await store.execute({
        sql: `INSERT INTO incidents(id,tenant_id,kind,subject_id,status,created_at,updated_at)
          VALUES ('incident-upgrade','tenant-upgrade','unknown_device_login','subject','received',?,?)`,
        args: ["2026-08-30T00:00:00.000Z", "2026-08-30T00:00:00.000Z"],
      });
      await store.execute({
        sql: `INSERT INTO workflow_runs(id,incident_id,tenant_id,run_id,workflow_id,status,started_at)
          VALUES ('workflow-upgrade','incident-upgrade','tenant-upgrade','run-upgrade','workflow','waiting',?)`,
        args: ["2026-08-30T00:00:00.000Z"],
      });
      await store.execute({
        sql: `INSERT INTO containment_plans(id,incident_id,tenant_id,schema_version,plan_version,plan_hash_version,plan_hash,plan_json,expires_at,created_at)
          VALUES ('plan-terminal','incident-upgrade','tenant-upgrade',1,2,1,?, '{}',?,?)`,
        args: [
          "b".repeat(64),
          "2026-08-30T01:00:00.000Z",
          "2026-08-30T00:00:00.000Z",
        ],
      });
      await store.execute({
        sql: `INSERT INTO approvals(id,plan_id,incident_id,tenant_id,plan_hash_version,plan_hash,requested_at,expires_at,decision,decided_by,decided_by_role,decided_at,workflow_run_id)
          VALUES ('approval-terminal','plan-terminal','incident-upgrade','tenant-upgrade',1,?,?,?,'approved','reviewer','soc_manager',?,'run-upgrade')`,
        args: [
          "b".repeat(64),
          "2026-08-30T00:00:00.000Z",
          "2026-08-30T01:00:00.000Z",
          "2026-08-30T00:00:03.000Z",
        ],
      });
      await store.execute({
        sql: `INSERT INTO provider_deliveries(id,provider,incident_id,tenant_id,operation,idempotency_key,status,attempt_count,next_attempt_at)
          VALUES ('provider-retry','mock-incident','incident-upgrade','tenant-upgrade','final-contained','key-retry','retry',1,?)`,
        args: ["2026-08-30T00:05:00.000Z"],
      });
      await store.execute({
        sql: `INSERT INTO containment_plans(id,incident_id,tenant_id,schema_version,plan_version,plan_hash_version,plan_hash,plan_json,expires_at,created_at)
          VALUES ('plan-upgrade','incident-upgrade','tenant-upgrade',1,1,1,?, '{}',?,?)`,
        args: [
          "a".repeat(64),
          "2026-08-30T01:00:00.000Z",
          "2026-08-30T00:00:00.000Z",
        ],
      });
      await store.execute({
        sql: `INSERT INTO approvals(id,plan_id,incident_id,tenant_id,plan_hash_version,plan_hash,requested_at,expires_at,workflow_run_id)
          VALUES ('approval-upgrade','plan-upgrade','incident-upgrade','tenant-upgrade',1,?,?,?,'run-upgrade')`,
        args: [
          "a".repeat(64),
          "2026-08-30T00:00:01.000Z",
          "2026-08-30T01:00:00.000Z",
        ],
      });
      await store.execute({
        sql: `INSERT INTO provider_deliveries(id,provider,incident_id,tenant_id,operation,idempotency_key,status,attempt_count,next_attempt_at)
          VALUES ('provider-upgrade','mock-incident','incident-upgrade','tenant-upgrade','open-awaiting-approval','key-upgrade','succeeded',1,NULL)`,
      });

      await migrateOperationalStore(store);
      await expect(
        store.execute({
          sql: "SELECT observed_at FROM provider_deliveries WHERE id='provider-upgrade'",
        }),
      ).resolves.toMatchObject({ rows: [{ observed_at: null }] });
      const exported = await exportAnalyticsSince(store, 0);
      expect(exported).toContainEqual(
        expect.objectContaining({
          source: "approvals",
          sourceId: "approval-upgrade",
          status: "pending",
          occurredAt: "2026-08-30T00:00:01.000Z",
        }),
      );
      expect(exported).toContainEqual(
        expect.objectContaining({
          sourceId: "provider-upgrade",
          withheld: { reason: "PROVIDER_OBSERVED_AT_UNKNOWN" },
        }),
      );
      expect(exported).toContainEqual(
        expect.objectContaining({
          sourceId: "provider-retry",
          occurredAt: "2026-08-30T00:05:00.000Z",
          withheld: { reason: "PROVIDER_OBSERVED_AT_UNKNOWN" },
        }),
      );
      expect(exported).toContainEqual(
        expect.objectContaining({
          sourceId: "approval-terminal",
          status: "pending",
          occurredAt: "2026-08-30T00:00:00.000Z",
        }),
      );
      expect(exported).toContainEqual(
        expect.objectContaining({
          sourceId: "approval-terminal",
          status: "approved",
          occurredAt: "2026-08-30T00:00:03.000Z",
        }),
      );
      const analyticsRoot = await mkdtemp(join(tmpdir(), "phase10-upgrade-"));
      const analytics = new DuckDbAnalyticsStore(
        join(analyticsRoot, "analytics.duckdb"),
      );
      try {
        await analytics.ingestBatch(exported);
        await analytics.rebuild(exported);
        await expect(
          analytics.queryMetric({
            metric: "approval_latency",
            tenantId: "tenant-upgrade",
            from: "2026-08-30T00:00:00.000Z",
            to: "2026-08-31T00:00:00.000Z",
          }),
        ).resolves.toMatchObject({ sampleCount: 1, value: 3000 });
        expect(await analytics.readWithheldRows()).toHaveLength(2);
        expect(
          (await analytics.readFactRows()).some(
            (row) => row.source === "provider_deliveries",
          ),
        ).toBe(false);
      } finally {
        await analytics.close();
        await rm(analyticsRoot, { recursive: true, force: true });
      }

      await store.execute({
        sql: `INSERT INTO provider_deliveries(id,provider,incident_id,tenant_id,operation,idempotency_key,status,attempt_count,next_attempt_at,observed_at)
          VALUES ('provider-live','mock-incident','incident-upgrade','tenant-upgrade','final-failed','key-live','succeeded',1,NULL,?)`,
        args: ["2026-08-30T00:00:03.000Z"],
      });
      const live = await exportAnalyticsSince(store, 0);
      expect(live).toContainEqual(
        expect.objectContaining({
          sourceId: "provider-live",
          occurredAt: "2026-08-30T00:00:03.000Z",
          status: "succeeded",
        }),
      );
    } finally {
      store.close();
    }
  });

  it("rejects checksum drift and converges concurrent starters", async () => {
    const firstDatabase = await createTempDatabase();
    databases.push(firstDatabase);
    const first = firstDatabase.createStore();
    const second = firstDatabase.createStore();
    try {
      await Promise.all([
        migrateOperationalStore(first),
        migrateOperationalStore(second),
      ]);
      await first.execute({
        sql: "UPDATE soc_schema_migrations SET checksum = 'tampered' WHERE version = 1",
      });
      await expect(migrateOperationalStore(first)).rejects.toMatchObject({
        code: "VALIDATION_FAILED",
      });
    } finally {
      first.close();
      second.close();
    }
  });

  it("pins executable migration identity and rejects semantic descriptor drift", async () => {
    const semanticDrift = {
      ...phase11CanonicalTenantReconciliationIntegrity,
      tenantPolicy: { maxCodePoints: 127 },
    };
    const checksum = migrationChecksum([], {
      schema: "soc-migration-integrity/v1",
      executable: phase11CanonicalTenantReconciliationIntegrity,
    });
    const driftedChecksum = migrationChecksum([], {
      schema: "soc-migration-integrity/v1",
      executable: semanticDrift,
    });
    expect(checksum).toBe(migrations[24]?.checksum);
    expect(driftedChecksum).not.toBe(checksum);
    const boundaryTenant = "a".repeat(128);
    expect(
      isCanonicalTenantId(
        boundaryTenant,
        phase11CanonicalTenantReconciliationIntegrity.tenantPolicy,
      ),
    ).toBe(true);
    expect(
      isCanonicalTenantId(boundaryTenant, semanticDrift.tenantPolicy),
    ).toBe(false);

    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      // Simulate a database produced by the published v23→v24 path without
      // using the current unsafe targetVersion route. Both historic checksums
      // remain intact; the normal upgrade applies only the new v25 anchor.
      await migrateOperationalStore(store, { targetVersion: 22 });
      await store.transaction(async (tx) => {
        await tx.batch(
          phase11CanonicalTenantReconciliationStatements.map((sql) => ({
            sql,
          })),
        );
        await tx.execute({
          sql: "INSERT INTO soc_schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
          args: [
            migrations[22]!.version,
            migrations[22]!.name,
            migrations[22]!.checksum,
            "2026-08-31T00:00:00.000Z",
          ],
        });
        await tx.execute({
          sql: "INSERT INTO soc_schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
          args: [
            migrations[23]!.version,
            migrations[23]!.name,
            migrations[23]!.checksum,
            "2026-08-31T00:00:00.000Z",
          ],
        });
      });
      await expect(migrateOperationalStore(store)).resolves.toBeUndefined();
      await expect(
        store.execute({
          sql: "SELECT version FROM soc_schema_migrations WHERE version = 25",
        }),
      ).resolves.toMatchObject({ rows: [{ version: 25 }] });
      await expect(migrateOperationalStore(store)).resolves.toBeUndefined();

      const driftedSet = migrations.map((migration) =>
        migration.version === 25
          ? {
              ...migration,
              checksum: driftedChecksum,
              integrity: {
                schema: "soc-migration-integrity/v1" as const,
                executable: semanticDrift,
              },
            }
          : migration,
      );
      await expect(
        migrateOperationalStore(store, { migrationSet: driftedSet }),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    } finally {
      store.close();
    }
  });

  it("rejects an executable migration without its anchor before any SQL", async () => {
    const execute = vi.fn();
    const transaction = vi.fn();
    await expect(
      migrateOperationalStore(
        { execute, transaction, close: () => {} },
        { targetVersion: 24 },
      ),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    expect(execute).not.toHaveBeenCalled();
    expect(transaction).not.toHaveBeenCalled();
  });

  it("rolls back an executable apply when its anchor cannot persist", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store, { targetVersion: 22 });
      await store.execute({
        sql: `CREATE TRIGGER reject_retention_integrity_anchor
          BEFORE INSERT ON soc_schema_migrations WHEN NEW.version = 25
          BEGIN SELECT RAISE(ABORT, 'anchor rejected'); END`,
      });
      await expect(migrateOperationalStore(store)).rejects.toBeDefined();
      await expect(
        store.execute({
          sql: "SELECT count(*) AS count FROM soc_schema_migrations WHERE version IN (23, 24, 25)",
        }),
      ).resolves.toMatchObject({ rows: [{ count: 0 }] });
      await expect(
        store.execute({
          sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'retention_source_cursors'",
        }),
      ).resolves.toMatchObject({
        rows: [{ name: "retention_source_cursors" }],
      });
    } finally {
      store.close();
    }
  });

  it("enforces plan-hash and provider-delivery idempotency in the database", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store);
      await store.execute({
        sql: `INSERT INTO incidents(
          id, tenant_id, kind, subject_id, status, created_at, updated_at
        ) VALUES ('incident-1', 'tenant-1', 'unknown_device_login', 'subject-1',
          'received', '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
      });
      await store.execute({
        sql: `INSERT INTO containment_plans(
          id, incident_id, tenant_id, schema_version, plan_version,
          plan_hash_version, plan_hash, plan_json, expires_at, created_at
        ) VALUES ('plan-1', 'incident-1', 'tenant-1', 1, 1, 1, ?, '{}',
          '2026-08-27T13:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
        args: ["a".repeat(64)],
      });
      await store.execute({
        sql: `INSERT INTO workflow_runs(
          id, incident_id, tenant_id, run_id, workflow_id, status, started_at
        ) VALUES ('workflow-row-1', 'incident-1', 'tenant-1', 'run-1',
          'incident-ingestion-workflow', 'running', '2026-08-27T12:00:00.000Z')`,
      });
      await store.execute({
        sql: `UPDATE incidents SET current_run_id = 'run-1'
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      await expect(
        store.execute({
          sql: `INSERT INTO containment_plans(
            id, incident_id, tenant_id, schema_version, plan_version,
            plan_hash_version, plan_hash, plan_json, expires_at, created_at
          ) VALUES ('plan-2', 'incident-1', 'tenant-1', 1, 2, 1, ?, '{}',
            '2026-08-27T13:00:00.000Z', '2026-08-27T12:01:00.000Z')`,
          args: ["a".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "CONFLICT" });

      await store.execute({
        sql: `INSERT INTO provider_deliveries(
          id, provider, incident_id, tenant_id, operation, idempotency_key, status
        ) VALUES ('delivery-1', 'linear', 'incident-1', 'tenant-1', 'create', 'key-1', 'pending')`,
      });
      await expect(
        store.execute({
          sql: `INSERT INTO provider_deliveries(
            id, provider, incident_id, tenant_id, operation, idempotency_key, status
          ) VALUES ('delivery-2', 'linear', 'incident-1', 'tenant-1', 'create', 'key-2', 'pending')`,
        }),
      ).rejects.toMatchObject({ code: "CONFLICT" });
    } finally {
      store.close();
    }
  });

  it("enforces tenant-scoped relationships, lowercase SHA-256 and UTC timestamps", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store);
      for (const [id, tenant] of [
        ["incident-1", "tenant-1"],
        ["incident-2", "tenant-2"],
      ] as const) {
        await store.execute({
          sql: `INSERT INTO incidents(
            id, tenant_id, kind, subject_id, status, created_at, updated_at
          ) VALUES (?, ?, 'unknown_device_login', 'subject-1', 'received',
            '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
          args: [id, tenant],
        });
      }
      await store.execute({
        sql: `INSERT INTO containment_plans(
          id, incident_id, tenant_id, schema_version, plan_version,
          plan_hash_version, plan_hash, plan_json, expires_at, created_at
        ) VALUES ('plan-1', 'incident-1', 'tenant-1', 1, 1, 1, ?, '{}',
          '2026-08-27T13:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
        args: ["a".repeat(64)],
      });

      await expect(
        store.execute({
          sql: `INSERT INTO containment_plans(
            id, incident_id, tenant_id, schema_version, plan_version,
            plan_hash_version, plan_hash, plan_json, expires_at, created_at
          ) VALUES ('cross-tenant-plan', 'incident-1', 'tenant-2', 1, 2, 1, ?, '{}',
            '2026-08-27T13:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
          args: ["b".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await expect(
        store.execute({
          sql: `INSERT INTO containment_actions(
            id, plan_id, incident_id, tenant_id, action_id, action_type, ordinal,
            input_json, idempotency_key, status
          ) VALUES ('cross-tenant-action', 'plan-1', 'incident-2', 'tenant-2',
            'action-1', 'revoke_session', 0, '{}', 'action-key', 'pending')`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `INSERT INTO approvals(
            id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
            requested_at, expires_at
          ) VALUES ('cross-tenant-approval', 'plan-1', 'incident-2', 'tenant-2', 1, ?,
            '2026-08-27T12:00:00.000Z', '2026-08-27T13:00:00.000Z')`,
          args: ["a".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `INSERT INTO approvals(
            id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
            requested_at, expires_at
          ) VALUES ('mismatched-hash-approval', 'plan-1', 'incident-1', 'tenant-1', 1, ?,
            '2026-08-27T12:00:00.000Z', '2026-08-27T13:00:00.000Z')`,
          args: ["b".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `UPDATE incidents SET current_plan_id = 'plan-1'
            WHERE tenant_id = 'tenant-2' AND id = 'incident-2'`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await expect(
        store.execute({
          sql: `INSERT INTO containment_plans(
            id, incident_id, tenant_id, schema_version, plan_version,
            plan_hash_version, plan_hash, plan_json, expires_at, created_at
          ) VALUES ('invalid-hash-plan', 'incident-1', 'tenant-1', 1, 2, 2, ?, '{}',
            '2026-08-27T13:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
          args: ["z".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `INSERT INTO alerts(
            id, incident_id, tenant_id, source, source_event_id, kind, occurred_at,
            subject_id, canonical_json, raw_payload_ref, schema_version, idempotency_key
          ) VALUES ('invalid-time-alert', 'incident-1', 'tenant-1', 'workos', 'event-2',
            'unknown_device_login', 'not-utc', 'subject-1', '{}', 'protected://alert/2', 1, 'key-2')`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      const actionForeignKeys = await store.execute({
        sql: "PRAGMA foreign_key_list(containment_actions)",
      });
      expect(
        actionForeignKeys.rows.filter(
          (row) => row.table === "containment_plans",
        ),
      ).toHaveLength(3);

      const tableDefinitions = await store.execute({
        sql: `SELECT name, sql FROM sqlite_master
          WHERE type = 'table' AND name IN (
            'incidents','alerts','evidence_items','workflow_runs','containment_plans',
            'approvals','timeline_events','authorized_devices','identity_snapshots',
            'provider_deliveries','outbox_events','dead_letter_events'
          )`,
      });
      const sqlByTable = new Map(
        tableDefinitions.rows.map((row) => [String(row.name), String(row.sql)]),
      );
      const timestampColumns = {
        incidents: ["created_at", "updated_at", "closed_at"],
        alerts: ["occurred_at"],
        evidence_items: ["observed_at", "collected_at"],
        workflow_runs: ["started_at", "finished_at"],
        containment_plans: ["expires_at", "created_at"],
        approvals: ["requested_at", "expires_at", "decided_at"],
        timeline_events: ["occurred_at"],
        authorized_devices: ["authorized_at", "revoked_at"],
        identity_snapshots: ["captured_at"],
        provider_deliveries: ["next_attempt_at"],
        outbox_events: ["occurred_at", "available_at", "published_at"],
        dead_letter_events: ["created_at", "resolved_at"],
      } as const;
      for (const [table, columns] of Object.entries(timestampColumns)) {
        const definition = sqlByTable.get(table);
        expect(definition, table).toBeDefined();
        for (const column of columns) {
          expect(definition, `${table}.${column}`).toMatch(
            new RegExp(`${column}[^,]*GLOB`),
          );
        }
      }
      for (const table of [
        "evidence_items",
        "containment_plans",
        "approvals",
        "identity_snapshots",
      ]) {
        expect(sqlByTable.get(table), table).toContain(
          "NOT GLOB '*[^0-9a-f]*'",
        );
      }
    } finally {
      store.close();
    }
  });

  it("enforces temporal ordering and nonempty audit envelope IDs", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    try {
      await migrateOperationalStore(store);
      await expect(
        store.execute({
          sql: `INSERT INTO incidents(
            id, tenant_id, kind, subject_id, status, created_at, updated_at
          ) VALUES ('regressing-incident', 'tenant-1', 'unknown_device_login',
            'subject-1', 'received', '2026-08-27T12:00:00.000Z',
            '2026-08-27T11:59:00.000Z')`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await store.execute({
        sql: `INSERT INTO incidents(
          id, tenant_id, kind, subject_id, status, created_at, updated_at
        ) VALUES ('incident-1', 'tenant-1', 'unknown_device_login', 'subject-1',
          'received', '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
      });
      await store.execute({
        sql: `UPDATE incidents SET updated_at = '2026-08-27T12:02:00.000Z'
          WHERE id = 'incident-1'`,
      });
      await expect(
        store.execute({
          sql: `UPDATE incidents SET updated_at = '2026-08-27T12:01:00.000Z'
            WHERE id = 'incident-1'`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await store.execute({
        sql: `INSERT INTO timeline_events(
          id, incident_id, tenant_id, sequence, type, category, correlation_id,
          payload_json, schema_version, occurred_at
        ) VALUES ('timeline-valid', 'incident-1', 'tenant-1', 1, 'event.created',
          'domain', 'correlation-1', '{}', 1, '2026-08-27T12:02:00.000Z')`,
      });
      await expect(
        store.execute({
          sql: `INSERT INTO timeline_events(
            id, incident_id, tenant_id, sequence, type, category, correlation_id,
            payload_json, schema_version, occurred_at
          ) VALUES ('timeline-regressing', 'incident-1', 'tenant-1', 2, 'event.created',
            'domain', 'correlation-1', '{}', 1, '2026-08-27T12:01:00.000Z')`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      await expect(
        store.execute({
          sql: `INSERT INTO containment_plans(
            id, incident_id, tenant_id, schema_version, plan_version,
            plan_hash_version, plan_hash, plan_json, expires_at, created_at
          ) VALUES ('invalid-time-plan', 'incident-1', 'tenant-1', 1, 1, 1, ?, '{}',
            '2026-08-27T11:59:00.000Z', '2026-08-27T12:00:00.000Z')`,
          args: ["a".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await store.execute({
        sql: `INSERT INTO containment_plans(
          id, incident_id, tenant_id, schema_version, plan_version,
          plan_hash_version, plan_hash, plan_json, expires_at, created_at
        ) VALUES ('plan-1', 'incident-1', 'tenant-1', 1, 1, 1, ?, '{}',
          '2026-08-27T13:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
        args: ["a".repeat(64)],
      });
      await store.execute({
        sql: `INSERT INTO workflow_runs(
          id, incident_id, tenant_id, run_id, workflow_id, status, started_at
        ) VALUES ('workflow-temporal', 'incident-1', 'tenant-1', 'run-1',
          'incident-ingestion-workflow', 'running', '2026-08-27T12:00:00.000Z')`,
      });
      await store.execute({
        sql: `UPDATE incidents SET current_run_id = 'run-1'
          WHERE tenant_id = 'tenant-1' AND id = 'incident-1'`,
      });
      await expect(
        store.execute({
          sql: `INSERT INTO approvals(
            id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
            requested_at, expires_at, workflow_run_id
          ) VALUES ('invalid-time-approval', 'plan-1', 'incident-1', 'tenant-1', 1, ?,
            '2026-08-27T12:01:00.000Z', '2026-08-27T12:00:00.000Z', 'run-1')`,
          args: ["a".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await store.execute({
        sql: `INSERT INTO approvals(
          id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
            requested_at, expires_at, workflow_run_id
          ) VALUES ('approval-1', 'plan-1', 'incident-1', 'tenant-1', 1, ?,
            '2026-08-27T12:02:00.000Z', '2026-08-27T13:00:00.000Z', 'run-1')`,
        args: ["a".repeat(64)],
      });
      await expect(
        store.execute({
          sql: `UPDATE approvals SET decision = 'approved', decided_by = 'manager-1',
            decided_by_role = 'soc_manager', decided_at = '2026-08-27T11:00:00.000Z'
            WHERE id = 'approval-1'`,
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      for (const [id, correlationId] of [
        ["", "correlation-1"],
        ["timeline-1", ""],
      ] as const) {
        await expect(
          store.execute({
            sql: `INSERT INTO timeline_events(
              id, incident_id, tenant_id, sequence, type, category, correlation_id,
              payload_json, schema_version, occurred_at
            ) VALUES (?, 'incident-1', 'tenant-1', 2, 'event.created', 'domain', ?,
              '{}', 1, '2026-08-27T12:03:00.000Z')`,
            args: [id, correlationId],
          }),
        ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      }
      for (const [id, runId, correlationId] of [
        ["outbox-empty-run", "", "correlation-1"],
        ["outbox-empty-correlation", "run-1", ""],
        ["", "run-1", "correlation-1"],
      ] as const) {
        await expect(
          store.execute({
            sql: `INSERT INTO outbox_events(
              id, type, run_id, incident_id, tenant_id, schema_version,
              correlation_id, payload_json, occurred_at, available_at
            ) VALUES (?, 'security.incident.updated', ?, 'incident-1', 'tenant-1', 1,
              ?, '{}', '2026-08-27T12:01:00.000Z', '2026-08-27T12:01:00.000Z')`,
            args: [id, runId, correlationId],
          }),
        ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });
      }
    } finally {
      store.close();
    }
  });
});
