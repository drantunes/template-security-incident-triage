/** Adds tenant attribution so retention's own append-only audit has a 365d policy. */
export const phase11RetentionAuditTenantStatements = [
  `ALTER TABLE retention_audit_events ADD COLUMN tenant_id TEXT`,
  `CREATE INDEX idx_retention_audit_tenant_occurred ON retention_audit_events(tenant_id, occurred_at)`,
] as const;
