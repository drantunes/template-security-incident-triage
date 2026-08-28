import { createHash } from "node:crypto";

import { operationalSchemaStatements } from "./0001-operational-schema.js";
import { operationalIndexStatements } from "./0002-operational-indexes.js";
import { runbookCatalogStatements } from "./0003-runbook-catalog.js";
import { runbookRetrievalStatements } from "./0004-runbook-retrieval.js";

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
]);
