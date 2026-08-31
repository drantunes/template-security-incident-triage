import { createHash } from "node:crypto";

import { operationalSchemaStatements } from "./0001-operational-schema.js";
import { operationalIndexStatements } from "./0002-operational-indexes.js";
import { runbookCatalogStatements } from "./0003-runbook-catalog.js";
import { runbookRetrievalStatements } from "./0004-runbook-retrieval.js";
import { evidenceIntegrityVersionStatements } from "./0005-evidence-integrity-version.js";
import { phase6ApprovalContainmentStatements } from "./0006-phase6-approval-containment.js";
import { phase8ProviderDurabilityStatements } from "./0007-phase8-provider-durability.js";
import { phase8AlertSourceDedupeStatements } from "./0008-phase8-alert-source-dedupe.js";
import { phase10AnalyticsExportStatements } from "./0009-phase10-analytics-export.js";
import { phase10TraceContextStatements } from "./0010-phase10-trace-context.js";
import { phase10TraceFenceStatements } from "./0011-phase10-trace-fence.js";
import { phase10EvalAuthorityStatements } from "./0012-phase10-eval-authority.js";
import { phase10RunbookAuthoritySnapshotStatements } from "./0013-phase10-runbook-authority-snapshot.js";
import { phase10ProviderObservedAtStatements } from "./0014-phase10-provider-observed-at.js";
import { phase10ApprovalHistoryStatements } from "./0015-phase10-approval-history.js";
import { phase11RetentionStatements } from "./0016-phase11-retention.js";
import { phase11RetentionClaimsStatements } from "./0017-phase11-retention-claims.js";
import { phase11RetentionAuditTenantStatements } from "./0018-phase11-retention-audit-tenant.js";
import { phase11RetentionSourceCursorStatements } from "./0019-phase11-retention-source-cursor.js";
import { phase11ConsumerLedgerTenantStatements } from "./0020-phase11-consumer-ledger-tenant.js";
import { phase11RetentionClaimsTenantKeyStatements } from "./0021-phase11-retention-claims-tenant-key.js";
import { phase11RetentionTenantBoundaryStatements } from "./0022-phase11-retention-tenant-boundaries.js";
import {
  phase11CanonicalTenantReconciliationStatements,
  phase11CanonicalTenantReconciliationIntegrity,
  phase11CanonicalTenantReconciliationLegacyIntegrity,
  reconcileCanonicalRetentionTenants,
} from "./0023-phase11-canonical-tenant-reconciliation.js";
import type { StoreTransaction } from "../operational-store.js";

export type Migration = Readonly<{
  version: number;
  name: string;
  checksum: string;
  statements: readonly string[];
  apply?: (tx: StoreTransaction) => Promise<void>;
  integrity?: MigrationIntegrityDescriptor;
  /** Forward anchor for a published v1 checksum whose apply cannot be changed. */
  integrityAnchor?: number;
}>;

export type MigrationIntegrityDescriptor = Readonly<{
  schema: "soc-migration-integrity/v1";
  executable: unknown;
}>;

export function migrationChecksum(
  statements: readonly string[],
  integrity?: MigrationIntegrityDescriptor,
): string {
  const material = integrity
    ? canonicalJson({ statements, integrity })
    : statements.join("\n");
  return createHash("sha256").update(material).digest("hex");
}

function defineMigration(
  version: number,
  name: string,
  statements: readonly string[],
  apply?: (tx: StoreTransaction) => Promise<void>,
  integrity?: MigrationIntegrityDescriptor,
  integrityAnchor?: number,
): Migration {
  if (apply && !integrity && integrityAnchor == null)
    throw new Error("MIGRATION_EXECUTABLE_INTEGRITY_REQUIRED");
  return Object.freeze({
    version,
    name,
    statements,
    checksum: migrationChecksum(statements, integrity),
    ...(apply ? { apply } : {}),
    ...(integrity ? { integrity } : {}),
    ...(integrityAnchor == null ? {} : { integrityAnchor }),
  });
}

export const migrations = Object.freeze([
  defineMigration(1, "operational-schema", operationalSchemaStatements),
  defineMigration(2, "operational-indexes", operationalIndexStatements),
  defineMigration(3, "runbook-catalog", runbookCatalogStatements),
  defineMigration(4, "runbook-retrieval", runbookRetrievalStatements),
  defineMigration(
    5,
    "evidence-integrity-version",
    evidenceIntegrityVersionStatements,
  ),
  defineMigration(
    6,
    "phase6-approval-containment",
    phase6ApprovalContainmentStatements,
  ),
  defineMigration(
    7,
    "phase8-provider-durability",
    phase8ProviderDurabilityStatements,
  ),
  defineMigration(
    8,
    "phase8-alert-source-dedupe",
    phase8AlertSourceDedupeStatements,
  ),
  defineMigration(
    9,
    "phase10-analytics-export",
    phase10AnalyticsExportStatements,
  ),
  defineMigration(10, "phase10-trace-context", phase10TraceContextStatements),
  defineMigration(11, "phase10-trace-fence", phase10TraceFenceStatements),
  defineMigration(12, "phase10-eval-authority", phase10EvalAuthorityStatements),
  defineMigration(
    13,
    "phase10-runbook-authority-snapshot",
    phase10RunbookAuthoritySnapshotStatements,
  ),
  defineMigration(
    14,
    "phase10-provider-observed-at",
    phase10ProviderObservedAtStatements,
  ),
  defineMigration(
    15,
    "phase10-approval-history",
    phase10ApprovalHistoryStatements,
  ),
  defineMigration(16, "phase11-retention", phase11RetentionStatements),
  defineMigration(
    17,
    "phase11-retention-claims",
    phase11RetentionClaimsStatements,
  ),
  defineMigration(
    18,
    "phase11-retention-audit-tenant",
    phase11RetentionAuditTenantStatements,
  ),
  defineMigration(
    19,
    "phase11-retention-source-cursor",
    phase11RetentionSourceCursorStatements,
  ),
  defineMigration(
    20,
    "phase11-consumer-ledger-tenant",
    phase11ConsumerLedgerTenantStatements,
  ),
  defineMigration(
    21,
    "phase11-retention-claims-tenant-key",
    phase11RetentionClaimsTenantKeyStatements,
  ),
  defineMigration(
    22,
    "phase11-retention-tenant-boundaries",
    phase11RetentionTenantBoundaryStatements,
  ),
  defineMigration(
    23,
    "phase11-canonical-tenant-reconciliation",
    phase11CanonicalTenantReconciliationStatements,
    reconcileCanonicalRetentionTenants,
    undefined,
    25,
  ),
  defineMigration(
    24,
    "phase11-canonical-tenant-reconciliation-integrity",
    [],
    undefined,
    {
      schema: "soc-migration-integrity/v1",
      executable: phase11CanonicalTenantReconciliationLegacyIntegrity,
    },
  ),
  defineMigration(
    25,
    "phase11-canonical-tenant-reconciliation-policy-integrity",
    [],
    undefined,
    {
      schema: "soc-migration-integrity/v1",
      executable: phase11CanonicalTenantReconciliationIntegrity,
    },
  ),
]);

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortCanonical(value));
}

function sortCanonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortCanonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, sortCanonical(nested)]),
    );
  return value;
}
