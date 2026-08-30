import type { OperationalStore } from "../db/operational-store.js";
import type { SanitizedTraceBoundary } from "../mastra/evals/trace-contract.js";

/**
 * Projects only verified, public Mastra trace clocks into the append-only
 * analytics journal.  It deliberately accepts sanitised boundaries rather
 * than a private Mastra storage schema.  The values are opaque ids, UTC
 * timestamps and integer durations only.
 */
export async function materializeVerifiedTraceObservations(
  store: OperationalStore,
  input: Readonly<{
    tenantId: string;
    incidentId: string;
    scenario: "privilege" | "country" | "device";
    traceId: string;
    boundaries: readonly SanitizedTraceBoundary[];
    requiredBoundaries: readonly string[];
  }>,
): Promise<void> {
  const completed = input.boundaries.find(
    (boundary) => boundary.name === "triage.completed",
  );
  const received = await store.execute({
    sql: `SELECT occurred_at FROM timeline_events WHERE tenant_id=? AND incident_id=?
      AND type='incident.received' ORDER BY sequence ASC LIMIT 1`,
    args: [input.tenantId, input.incidentId],
  });
  const receivedAt = Date.parse(String(received.rows[0]?.occurred_at ?? ""));
  if (
    !completed?.endMs ||
    !Number.isFinite(receivedAt) ||
    completed.endMs < receivedAt
  )
    throw new Error("PHASE10_ANALYTICS_TRACE_CLOCK_INVALID");
  const completedAt = completed.endMs;
  const events = [
    ...input.boundaries
      .filter(
        (boundary) =>
          boundary.endMs !== undefined &&
          typeof boundary.attributes.stepId === "string",
      )
      .map((boundary) => ({
        id: `trace-step:${boundary.spanId}`,
        occurredAt: new Date(boundary.endMs!).toISOString(),
        category: "trace.step.duration",
        status: `duration-ms:${Math.max(0, boundary.endMs! - boundary.startMs)}`,
      })),
    {
      id: `trace-triage:${input.traceId}`,
      occurredAt: new Date(completedAt).toISOString(),
      category: "trace.triage.latency",
      status: `duration-ms:${completedAt - receivedAt}`,
    },
    ...input.requiredBoundaries.map((name) => ({
      id: `trace-boundary:${input.traceId}:${name}`,
      occurredAt: new Date(completedAt).toISOString(),
      category: "trace.boundary",
      status: input.boundaries.some((boundary) => boundary.name === name)
        ? "present"
        : "missing",
    })),
  ];
  for (const event of events) {
    const snapshot = JSON.stringify({
      id: event.id,
      tenant_id: input.tenantId,
      incident_id: input.incidentId,
      occurred_at: event.occurredAt,
      category: event.category,
      status: event.status,
      scenario: input.scenario,
    });
    const exists = await store.execute({
      sql: `SELECT snapshot_json FROM analytics_export_events
        WHERE source='timeline_events' AND source_id=? AND source_version='trace-v1'`,
      args: [event.id],
    });
    if (exists.rows[0]) {
      if (exists.rows[0].snapshot_json !== snapshot)
        throw new Error("PHASE10_ANALYTICS_TRACE_CONFLICT");
      continue;
    }
    await store.execute({
      sql: `INSERT INTO analytics_export_events(source,source_id,source_version,changed_at,snapshot_json)
        VALUES ('timeline_events',?,'trace-v1',?,?)`,
      args: [event.id, event.occurredAt, snapshot],
    });
  }
}
