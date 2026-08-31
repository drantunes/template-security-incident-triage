/** Durable, opaque continuation for the Phase 10 audit trace. */
export const phase10TraceContextStatements = [
  `ALTER TABLE workflow_runs ADD COLUMN phase10_trace_json TEXT
    CHECK(phase10_trace_json IS NULL OR json_valid(phase10_trace_json))`,
  // The carrier is not immutable: every completed boundary advances its
  // parent span.  Writers use a compare-and-swap predicate in
  // phase10-trace-context.ts, so an older worker cannot overwrite a newer
  // continuation after resume/retry.
] as const;
