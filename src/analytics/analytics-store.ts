export type AnalyticsSource =
  "timeline_events" | "provider_deliveries" | "approvals" | "eval_results";

export type AnalyticsRecord = Readonly<{
  sequence: number;
  source: AnalyticsSource;
  sourceId: string;
  sourceVersion: string;
  tenantId: string;
  incidentId?: string;
  occurredAt: string;
  category: string;
  status?: string;
  /** Versioned source projection; never inferred from an aggregate category. */
  scenario?: "privilege" | "country" | "device";
  /** Digest of the immutable, sanitised journal snapshot. */
  checksum: string;
  /**
   * An authenticated journal entry that deliberately advances the global
   * cursor without becoming a metric fact. Its source timestamp is unknown.
   */
  withheld?: Readonly<{ reason: "PROVIDER_OBSERVED_AT_UNKNOWN" }>;
}>;

export const analyticsMetricIds = [
  "triage_latency",
  "step_duration",
  "provider_failure_rate",
  "escalation_accuracy",
  "approval_latency",
  "guardrail_block_rate",
  "containment_execution_rate",
  "audit_trace_completeness",
] as const;
export type AnalyticsMetricId = (typeof analyticsMetricIds)[number];
export type AnalyticsMetricResult = Readonly<{
  sampleCount: number;
  value: number | null;
  reason?: "NO_DATA";
  /** Present for latency/duration metrics; values are milliseconds. */
  distribution?: Readonly<{ p50: number; p95: number; max: number }>;
}>;

export interface AnalyticsStore {
  migrate(): Promise<void>;
  ingestBatch(records: readonly AnalyticsRecord[]): Promise<void>;
  readCursor(source: AnalyticsSource): Promise<number>;
  queryMetric(
    input: Readonly<{
      metric: AnalyticsMetricId;
      tenantId: string;
      from: string;
      to: string;
      scenario?: string;
    }>,
  ): Promise<AnalyticsMetricResult>;
  rebuild(records: readonly AnalyticsRecord[]): Promise<void>;
  close(): Promise<void>;
}
