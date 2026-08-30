/**
 * Forward-only reconstruction of the missing pending side of approvals that
 * were terminal before the Phase 10 journal existed. Both timestamps are
 * already authoritative columns in the operational approval ledger.
 */
export const phase10ApprovalHistoryStatements = [
  `INSERT INTO analytics_export_events(source, source_id, source_version, changed_at, snapshot_json)
    SELECT 'approvals', a.id, printf('%s:pending:backfill-v2', a.requested_at), a.requested_at,
      json_object('id',a.id,'tenant_id',a.tenant_id,'incident_id',a.incident_id,'occurred_at',a.requested_at,'category','approval','status','pending','scenario',
        (SELECT CASE kind WHEN 'unauthorized_privilege_change' THEN 'privilege' WHEN 'disallowed_country_login' THEN 'country' ELSE 'device' END FROM incidents i WHERE i.tenant_id=a.tenant_id AND i.id=a.incident_id))
    FROM approvals a
    WHERE (a.decision IS NOT NULL OR a.expiry_resumed_at IS NOT NULL)
      AND NOT EXISTS (
        SELECT 1 FROM analytics_export_events e
        WHERE e.source='approvals' AND e.source_id=a.id
          AND json_extract(e.snapshot_json,'$.status')='pending'
      )
    ORDER BY a.requested_at, a.id`,
] as const;
