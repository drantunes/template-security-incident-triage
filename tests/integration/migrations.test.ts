import { afterEach, describe, expect, it } from "vitest";

import { migrateOperationalStore } from "../../src/db/migrate.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("SOC migrations", () => {
  it("creates all 13 tables, constraints and indexes from an empty database", async () => {
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
            'identity_snapshots','provider_deliveries','outbox_events','dead_letter_events'
          )) ORDER BY name`,
      });
      expect(tables.rows).toHaveLength(14);
      expect(tables.rows.map((row) => row.name)).toContain(
        "soc_schema_migrations",
      );

      const indexes = await store.execute({
        sql: "SELECT count(*) AS count FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
      });
      expect(Number(indexes.rows[0]?.count)).toBe(17);

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

  it("supports 0001 to 0002 upgrade, no-op reapplication and reopening", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    let store = database.createStore();
    await migrateOperationalStore(store, { targetVersion: 1 });
    await store.execute({
      sql: `INSERT INTO incidents(
        id, tenant_id, kind, subject_id, status, created_at, updated_at
      ) VALUES ('incident-preserved', 'tenant-1', 'unknown_device_login', 'subject-1',
        'received', '2026-08-27T12:00:00.000Z', '2026-08-27T12:00:00.000Z')`,
    });
    await migrateOperationalStore(store);
    await migrateOperationalStore(store);
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
      expect(ledger.rows).toEqual([{ version: 1 }, { version: 2 }]);
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
      await expect(
        store.execute({
          sql: `INSERT INTO approvals(
            id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
            requested_at, expires_at
          ) VALUES ('invalid-time-approval', 'plan-1', 'incident-1', 'tenant-1', 1, ?,
            '2026-08-27T12:01:00.000Z', '2026-08-27T12:00:00.000Z')`,
          args: ["a".repeat(64)],
        }),
      ).rejects.toMatchObject({ code: "STORAGE_UNAVAILABLE" });

      await store.execute({
        sql: `INSERT INTO approvals(
          id, plan_id, incident_id, tenant_id, plan_hash_version, plan_hash,
          requested_at, expires_at
        ) VALUES ('approval-1', 'plan-1', 'incident-1', 'tenant-1', 1, ?,
          '2026-08-27T12:02:00.000Z', '2026-08-27T13:00:00.000Z')`,
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
