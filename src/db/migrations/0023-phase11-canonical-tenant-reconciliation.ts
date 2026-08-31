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

/**
 * Stable, executable-plan identity. Migration 0024 hashes this descriptor
 * atomically with the 0023 reconciliation on fresh upgrades. It is explicit
 * rather than derived from a function's source, so formatting and runtime
 * differences cannot silently change the migration's identity.
 */
export const phase11CanonicalTenantReconciliationIntegrity = Object.freeze({
  schema: "phase11-canonical-tenant-reconciliation/v1",
  tenantPredicate: "isCanonicalTenantId/v1",
  quarantine: "RETENTION_TENANT_NONCANONICAL",
  copies: [
    {
      sourceTable: "retention_source_cursors_v22_reconciliation_source",
      columns: ["tenant_id", "next_source"],
      insertSql:
        "INSERT INTO retention_source_cursors(tenant_id, next_source) VALUES (?, ?)",
    },
    {
      sourceTable: "retention_tombstone_claims_v22_reconciliation_source",
      columns: [
        "source",
        "source_identity",
        "tenant_id",
        "retention_class",
        "disposition",
        "aged_at",
        "tombstoned_at",
        "sweep_id",
      ],
      insertSql: `INSERT INTO retention_tombstone_claims(
        source, source_identity, tenant_id, retention_class, disposition, aged_at, tombstoned_at, sweep_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    },
  ],
});

export async function reconcileCanonicalRetentionTenants(
  tx: StoreTransaction,
): Promise<void> {
  await tx.batch(
    phase11CanonicalTenantReconciliationStatements.map((sql) => ({ sql })),
  );
  const quarantinedAt = new Date().toISOString();
  for (const copy of phase11CanonicalTenantReconciliationIntegrity.copies)
    await copyRows(tx, copy, quarantinedAt);
}

async function copyRows(
  tx: StoreTransaction,
  copy: (typeof phase11CanonicalTenantReconciliationIntegrity.copies)[number],
  quarantinedAt: string,
): Promise<void> {
  const result = await tx.execute({
    sql: `SELECT ${copy.columns.join(", ")} FROM ${copy.sourceTable}`,
  });
  for (const row of result.rows) {
    const tenantId = row.tenant_id;
    if (isCanonicalTenantId(tenantId)) {
      const args: readonly InValue[] = copy.columns.map(
        (column) => row[column] ?? null,
      );
      await tx.execute({ sql: copy.insertSql, args });
      continue;
    }
    await tx.execute({
      sql: `INSERT INTO retention_tenant_quarantine(
        source_table, tenant_id, payload_json, reason, quarantined_at
      ) VALUES (?, ?, ?, ?, ?)`,
      args: [
        copy.sourceTable,
        typeof tenantId === "string" ? tenantId : null,
        JSON.stringify(row),
        phase11CanonicalTenantReconciliationIntegrity.quarantine,
        quarantinedAt,
      ],
    });
  }
}
