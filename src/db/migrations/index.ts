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

export type Migration = Readonly<{
  version: number;
  name: string;
  checksum: string;
  statements: readonly string[];
}>;

function defineMigration(
  version: number,
  name: string,
  statements: readonly string[],
): Migration {
  return Object.freeze({
    version,
    name,
    statements,
    checksum: createHash("sha256").update(statements.join("\n")).digest("hex"),
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
]);
