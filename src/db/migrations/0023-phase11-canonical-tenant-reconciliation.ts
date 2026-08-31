import type { InValue } from "@libsql/client";

import { isCanonicalTenantId } from "../../schemas/common.js";
import type { StoreTransaction } from "../operational-store.js";

/**
 * Rebuilds the two retention-owned tenant indexes after the v22 SQL-only
 * boundary. SQLite cannot express every ECMAScript whitespace code point, so
 * the copy is deliberately performed through the shared JavaScript predicate.
 * Non-canonical rows are withheld with their original payload; no tenant is
 * inferred or normalized during reconciliation.
 */
export const phase11CanonicalTenantReconciliationStatements = [
  `ALTER TABLE retention_source_cursors RENAME TO retention_source_cursors_v22_reconciliation_source`,
  `ALTER TABLE retention_tombstone_claims RENAME TO retention_tombstone_claims_v22_reconciliation_source`,
  `CREATE TABLE retention_tenant_quarantine (
    source_table TEXT NOT NULL,
    tenant_id TEXT,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    reason TEXT NOT NULL,
    quarantined_at TEXT NOT NULL CHECK(quarantined_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY(source_table, payload_json)
  ) STRICT`,
  `CREATE TABLE retention_source_cursors (
    tenant_id TEXT PRIMARY KEY CHECK(length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id),
    next_source INTEGER NOT NULL CHECK(next_source >= 0)
  ) STRICT`,
  `CREATE TABLE retention_tombstone_claims (
    source TEXT NOT NULL CHECK(length(trim(source)) BETWEEN 1 AND 128),
    source_identity TEXT NOT NULL CHECK(json_valid(source_identity)),
    tenant_id TEXT NOT NULL CHECK(length(tenant_id) BETWEEN 1 AND 128 AND trim(tenant_id) = tenant_id),
    retention_class TEXT NOT NULL CHECK(retention_class IN ('thirty-day','three-hundred-sixty-five-day')),
    disposition TEXT NOT NULL CHECK(disposition IN ('deleted','minimized','retained-authority')),
    aged_at TEXT NOT NULL CHECK(aged_at GLOB '????-??-??T??:??:??.???Z'),
    tombstoned_at TEXT NOT NULL CHECK(tombstoned_at GLOB '????-??-??T??:??:??.???Z'),
    sweep_id TEXT NOT NULL CHECK(length(trim(sweep_id)) BETWEEN 1 AND 128),
    PRIMARY KEY(source, tenant_id, source_identity)
  ) STRICT`,
  `CREATE INDEX idx_retention_tombstone_claims_tenant_v23 ON retention_tombstone_claims(tenant_id, tombstoned_at)`,
  `CREATE TRIGGER retention_tombstone_claims_v23_append_only_update BEFORE UPDATE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
  `CREATE TRIGGER retention_tombstone_claims_v23_append_only_delete BEFORE DELETE ON retention_tombstone_claims
    BEGIN SELECT RAISE(ABORT, 'PHASE11_RETENTION_APPEND_ONLY'); END`,
] as const;

export async function reconcileCanonicalRetentionTenants(
  tx: StoreTransaction,
): Promise<void> {
  await tx.batch(
    phase11CanonicalTenantReconciliationStatements.map((sql) => ({ sql })),
  );
  const quarantinedAt = new Date().toISOString();
  await copyRows(
    tx,
    "retention_source_cursors_v22_reconciliation_source",
    ["tenant_id", "next_source"],
    `INSERT INTO retention_source_cursors(tenant_id, next_source) VALUES (?, ?)`,
    quarantinedAt,
  );
  await copyRows(
    tx,
    "retention_tombstone_claims_v22_reconciliation_source",
    [
      "source",
      "source_identity",
      "tenant_id",
      "retention_class",
      "disposition",
      "aged_at",
      "tombstoned_at",
      "sweep_id",
    ],
    `INSERT INTO retention_tombstone_claims(
      source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    quarantinedAt,
  );
}

async function copyRows(
  tx: StoreTransaction,
  sourceTable: string,
  columns: readonly string[],
  insertSql: string,
  quarantinedAt: string,
): Promise<void> {
  const result = await tx.execute({
    sql: `SELECT ${columns.join(", ")} FROM ${sourceTable}`,
  });
  for (const row of result.rows) {
    const tenantId = row.tenant_id;
    if (isCanonicalTenantId(tenantId)) {
      const args: readonly InValue[] = columns.map(
        (column) => row[column] ?? null,
      );
      await tx.execute({ sql: insertSql, args });
      continue;
    }
    await tx.execute({
      sql: `INSERT INTO retention_tenant_quarantine(
        source_table, tenant_id, payload_json, reason, quarantined_at
      ) VALUES (?, ?, ?, ?, ?)`,
      args: [
        sourceTable,
        typeof tenantId === "string" ? tenantId : null,
        JSON.stringify(row),
        "RETENTION_TENANT_NONCANONICAL",
        quarantinedAt,
      ],
    });
  }
}
