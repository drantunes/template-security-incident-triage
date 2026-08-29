/**
 * Correct the unpublished Phase 8 durability delta without rewriting its
 * checksum. Alert event identifiers are scoped by provider source, matching
 * the baseline UNIQUE(source, source_event_id) contract.
 */
export const phase8AlertSourceDedupeStatements = [
  `DROP INDEX IF EXISTS idx_alerts_source_event_id_global`,
] as const;
