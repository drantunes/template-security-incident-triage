/** Persists tenant-local source rotation so bounded retention batches make progress. */
export const phase11RetentionSourceCursorStatements = [
  `CREATE TABLE retention_source_cursors (
    tenant_id TEXT PRIMARY KEY,
    next_source INTEGER NOT NULL CHECK(next_source >= 0)
  )`,
] as const;
