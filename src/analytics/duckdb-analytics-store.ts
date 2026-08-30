import { mkdir, open, rename, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname } from "node:path";

import { DuckDBInstance, type DuckDBConnection } from "@duckdb/node-api";

import type {
  AnalyticsMetricId,
  AnalyticsMetricResult,
  AnalyticsRecord,
  AnalyticsSource,
  AnalyticsStore,
} from "./analytics-store.js";
import {
  analyticsSchemaChecksum,
  analyticsSchemaStatements,
  analyticsSchemaVersion,
} from "./schema.js";

const sources: readonly AnalyticsSource[] = [
  "timeline_events",
  "provider_deliveries",
  "approvals",
  "eval_results",
];

export class DuckDbAnalyticsStore implements AnalyticsStore {
  private connection?: DuckDBConnection;
  private instance?: DuckDBInstance;
  private lock?: Awaited<ReturnType<typeof open>>;

  constructor(private readonly path = ".mastra/analytics/phase10.duckdb") {}

  async migrate(): Promise<void> {
    // A validation error during a caller's first open must not leave a writer
    // lock/FileHandle for GC to clean up. Once a store is already live, later
    // operation failures deliberately retain its owned connection and lock.
    const openedBeforeMigration = this.connection !== undefined;
    try {
      const connection = await this.open();
      for (const statement of analyticsSchemaStatements)
        await connection.run(statement);
      const existingVersions = await (
        await connection.run(
          "SELECT version, checksum FROM analytics_schema_versions ORDER BY version",
        )
      ).getRowObjectsJS();
      // A derived file is never upgraded in place: C1 froze the public layout at
      // v1. Opening a different layout fails closed so callers rebuild it from
      // the authoritative LibSQL journal instead of mixing facts.
      if (
        existingVersions.some(
          (row) =>
            Number(row.version) !== analyticsSchemaVersion ||
            String(row.checksum) !== analyticsSchemaChecksum,
        )
      )
        throw new Error("PHASE10_ANALYTICS_SCHEMA_INVALID");
      await connection.run(
        "INSERT OR IGNORE INTO analytics_schema_versions VALUES ($1, $2, '2026-08-30T00:00:00.000Z')",
        [analyticsSchemaVersion, analyticsSchemaChecksum],
      );
      const schema = await connection.run(
        "SELECT checksum FROM analytics_schema_versions WHERE version=$1",
        [analyticsSchemaVersion],
      );
      if (
        (await schema.getRowObjectsJS())[0]?.checksum !==
        analyticsSchemaChecksum
      )
        throw new Error("PHASE10_ANALYTICS_SCHEMA_INVALID");
      for (const source of sources)
        await connection.run(
          "INSERT OR IGNORE INTO ingest_cursors VALUES ($1, 0, '', $2)",
          [source, analyticsSchemaVersion],
        );
      await connection.run(
        "INSERT OR IGNORE INTO analytics_ingest_state VALUES (1,0,0,'', $1)",
        [analyticsSchemaVersion],
      );
      const cursorRows = await (
        await connection.run(
          "SELECT source, schema_version FROM ingest_cursors ORDER BY source",
        )
      ).getRowObjectsJS();
      if (
        cursorRows.length !== sources.length ||
        cursorRows.some(
          (row) =>
            !sources.includes(row.source as AnalyticsSource) ||
            Number(row.schema_version) !== analyticsSchemaVersion,
        )
      )
        throw new Error("PHASE10_ANALYTICS_SCHEMA_INVALID");
      const stateRows = await (
        await connection.run(
          "SELECT schema_version FROM analytics_ingest_state WHERE id=1",
        )
      ).getRowObjectsJS();
      if (Number(stateRows[0]?.schema_version) !== analyticsSchemaVersion)
        throw new Error("PHASE10_ANALYTICS_SCHEMA_INVALID");
    } catch (error) {
      if (!openedBeforeMigration) await this.closeAfterFailedOpen();
      throw error;
    }
  }

  async ingestBatch(records: readonly AnalyticsRecord[]): Promise<void> {
    await this.migrate();
    const ordered = [...records].sort(
      (left, right) =>
        left.sequence - right.sequence ||
        left.source.localeCompare(right.source) ||
        left.sourceId.localeCompare(right.sourceId),
    );
    const connection = await this.open();
    await connection.run("BEGIN TRANSACTION");
    try {
      const stateRows = await (
        await connection.run(
          "SELECT last_sequence,record_count,checksum,schema_version FROM analytics_ingest_state WHERE id=1",
        )
      ).getRowObjectsJS();
      const state = stateRows[0];
      if (!state || Number(state.schema_version) !== analyticsSchemaVersion)
        throw new Error("PHASE10_ANALYTICS_SCHEMA_INVALID");
      let lastSequence = Number(state.last_sequence);
      let recordCount = Number(state.record_count);
      let digest = String(state.checksum);
      for (const row of ordered) {
        if (
          !Number.isSafeInteger(row.sequence) ||
          row.sequence < 1 ||
          !sources.includes(row.source) ||
          !/^[a-f0-9]{64}$/u.test(row.checksum) ||
          !Number.isFinite(Date.parse(row.occurredAt))
        )
          throw new Error("PHASE10_ANALYTICS_RECORD_INVALID");
        if (row.withheld) {
          const existing = await connection.run(
            `SELECT source,source_id,source_version,reason,checksum
             FROM analytics_withheld_events WHERE sequence=$1`,
            [row.sequence],
          );
          const existingRows = await existing.getRowObjectsJS();
          if (existingRows.length) {
            const current = existingRows[0]!;
            if (
              current.source !== row.source ||
              current.source_id !== row.sourceId ||
              current.source_version !== row.sourceVersion ||
              current.reason !== row.withheld.reason ||
              current.checksum !== row.checksum
            )
              throw new Error("PHASE10_ANALYTICS_IDEMPOTENCY_CONFLICT");
          } else {
            const factAtSequence = await connection.run(
              "SELECT 1 FROM analytics_facts WHERE sequence=$1",
              [row.sequence],
            );
            if ((await factAtSequence.getRowObjectsJS()).length)
              throw new Error("PHASE10_ANALYTICS_IDEMPOTENCY_CONFLICT");
            if (row.sequence !== lastSequence + 1)
              throw new Error("PHASE10_ANALYTICS_CURSOR_GAP");
            await connection.run(
              `INSERT INTO analytics_withheld_events
               VALUES ($1,$2,$3,$4,$5,$6)`,
              [
                row.sequence,
                row.source,
                row.sourceId,
                row.sourceVersion,
                row.withheld.reason,
                row.checksum,
              ],
            );
            lastSequence = row.sequence;
            recordCount++;
            digest = combineChecksum(digest, row.checksum);
          }
          await connection.run(
            `UPDATE ingest_cursors SET last_sequence = GREATEST(last_sequence, $1), last_source_id = CASE WHEN last_sequence <= $1 THEN $2 ELSE last_source_id END WHERE source = $3`,
            [row.sequence, row.sourceId, row.source],
          );
          continue;
        }
        const existing = await connection.run(
          `SELECT sequence,tenant_id,incident_id,occurred_at,category,status,scenario,checksum FROM analytics_facts WHERE source=$1 AND source_id=$2 AND source_version=$3`,
          [row.source, row.sourceId, row.sourceVersion],
        );
        const existingRows = await existing.getRowObjectsJS();
        if (existingRows.length) {
          const current = existingRows[0]!;
          if (
            Number(current.sequence) !== row.sequence ||
            current.tenant_id !== row.tenantId ||
            current.incident_id !== (row.incidentId ?? null) ||
            Date.parse(String(current.occurred_at)) !==
              Date.parse(row.occurredAt) ||
            current.category !== row.category ||
            current.status !== (row.status ?? null) ||
            current.scenario !== (row.scenario ?? null) ||
            current.checksum !== row.checksum
          )
            throw new Error("PHASE10_ANALYTICS_IDEMPOTENCY_CONFLICT");
        } else {
          const withheldAtSequence = await connection.run(
            "SELECT 1 FROM analytics_withheld_events WHERE sequence=$1",
            [row.sequence],
          );
          if ((await withheldAtSequence.getRowObjectsJS()).length)
            throw new Error("PHASE10_ANALYTICS_IDEMPOTENCY_CONFLICT");
          if (row.sequence !== lastSequence + 1)
            throw new Error("PHASE10_ANALYTICS_CURSOR_GAP");
          await connection.run(
            `INSERT INTO analytics_facts VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              row.source,
              row.sourceId,
              row.sourceVersion,
              row.sequence,
              row.tenantId,
              row.incidentId ?? null,
              row.occurredAt,
              row.category,
              row.status ?? null,
              row.scenario ?? null,
              row.checksum,
            ],
          );
          lastSequence = row.sequence;
          recordCount++;
          digest = combineChecksum(digest, row.checksum);
        }
        await connection.run(
          `UPDATE ingest_cursors SET last_sequence = GREATEST(last_sequence, $1), last_source_id = CASE WHEN last_sequence <= $1 THEN $2 ELSE last_source_id END WHERE source = $3`,
          [row.sequence, row.sourceId, row.source],
        );
      }
      await connection.run(
        "UPDATE analytics_ingest_state SET last_sequence=$1,record_count=$2,checksum=$3 WHERE id=1",
        [lastSequence, recordCount, digest],
      );
      await connection.run("COMMIT");
    } catch (error) {
      await connection.run("ROLLBACK");
      throw error;
    }
  }

  async readCursor(source: AnalyticsSource): Promise<number> {
    await this.migrate();
    const result = await (
      await this.open()
    ).run("SELECT last_sequence FROM ingest_cursors WHERE source = $1", [
      source,
    ]);
    const rows = await result.getRowObjectsJS();
    return Number(rows[0]?.last_sequence ?? 0);
  }

  async queryMetric(
    input: Readonly<{
      metric: AnalyticsMetricId;
      tenantId: string;
      from: string;
      to: string;
      scenario?: string;
    }>,
  ): Promise<AnalyticsMetricResult> {
    validateMetricQueryInput(input);
    await this.migrate();
    const metric = metricQuery(input.metric);
    // Scenario is projected from the immutable journal snapshot.  It is never
    // guessed from an event name after aggregation.
    const result = await (
      await this.open()
    ).run(metric.sql, [
      input.tenantId,
      input.from,
      input.to,
      input.scenario ?? null,
    ]);
    const rows = await result.getRowObjectsJS();
    const sampleCount = Number(rows[0]?.sample_count ?? 0);
    return sampleCount
      ? {
          sampleCount,
          value: Number(rows[0]?.value),
          ...(rows[0]?.p50 === undefined
            ? {}
            : {
                distribution: {
                  p50: Number(rows[0].p50),
                  p95: Number(rows[0].p95),
                  max: Number(rows[0].max),
                },
              }),
        }
      : { sampleCount: 0, value: null, reason: "NO_DATA" };
  }

  async rebuild(records: readonly AnalyticsRecord[]): Promise<void> {
    await this.close();
    const temporary = `${this.path}.rebuild`;
    await rm(temporary, { force: true });
    const replacement = new DuckDbAnalyticsStore(temporary);
    try {
      await replacement.ingestBatch(records);
      await replacement.assertIntegrity(records);
      await replacement.close();
      await mkdir(dirname(this.path), { recursive: true });
      await rename(temporary, this.path);
    } catch (error) {
      await replacement.close();
      await rm(temporary, { force: true });
      throw error;
    }
  }

  async assertIntegrity(records: readonly AnalyticsRecord[]): Promise<void> {
    await this.migrate();
    const rows = await (
      await this.open()
    ).run(
      "SELECT last_sequence,record_count,checksum FROM analytics_ingest_state WHERE id=1",
    );
    const state = (await rows.getRowObjectsJS())[0];
    const ordered = [...records].sort((a, b) => a.sequence - b.sequence);
    const checksum = ordered.reduce(
      (current, row) => combineChecksum(current, row.checksum),
      "",
    );
    if (
      !state ||
      Number(state.last_sequence) !== (ordered.at(-1)?.sequence ?? 0) ||
      Number(state.record_count) !== ordered.length ||
      state.checksum !== checksum
    )
      throw new Error("PHASE10_ANALYTICS_INTEGRITY_INVALID");
  }

  /**
   * Read the exact derived rows that a Phase 10 report is about to expose.
   * This intentionally has no payload columns: the analytics model only owns
   * the schema-safe projection persisted in `analytics_facts`.
   */
  async readFactRows(): Promise<readonly Record<string, unknown>[]> {
    await this.migrate();
    return (
      await (
        await this.open()
      ).run(
        `SELECT source,source_id,source_version,sequence,tenant_id,incident_id,
                occurred_at,category,status,scenario,checksum
         FROM analytics_facts ORDER BY sequence,source,source_id`,
      )
    ).getRowObjectsJS();
  }

  /** Audit-only journal tombstones; they are intentionally absent from metrics. */
  async readWithheldRows(): Promise<readonly Record<string, unknown>[]> {
    await this.migrate();
    return (
      await (
        await this.open()
      ).run(
        `SELECT sequence,source,source_id,source_version,reason,checksum
         FROM analytics_withheld_events ORDER BY sequence`,
      )
    ).getRowObjectsJS();
  }

  async close(): Promise<void> {
    const connection = this.connection;
    const instance = this.instance;
    // Clear ownership before close calls so an idempotent retry never reaches
    // a FileHandle already being released by a prior cleanup path.
    this.connection = undefined;
    this.instance = undefined;
    const ownedLock = this.lock;
    this.lock = undefined;
    let firstError: unknown;
    try {
      connection?.closeSync();
    } catch (error) {
      firstError = error;
    }
    try {
      instance?.closeSync();
    } catch (error) {
      firstError ??= error;
    }
    try {
      await ownedLock?.close();
    } catch (error) {
      firstError ??= error;
    } finally {
      if (ownedLock) await rm(`${this.path}.phase10.lock`, { force: true });
    }
    if (firstError) throw firstError;
  }

  private async open(): Promise<DuckDBConnection> {
    if (this.connection) return this.connection;
    await mkdir(dirname(this.path), { recursive: true });
    try {
      this.lock = await open(`${this.path}.phase10.lock`, "wx");
    } catch {
      throw new Error("PHASE10_ANALYTICS_WRITER_LOCKED");
    }
    try {
      this.instance = await DuckDBInstance.create(this.path);
      this.connection = await this.instance.connect();
      return this.connection;
    } catch (error) {
      await this.closeAfterFailedOpen();
      throw error;
    }
  }

  private async closeAfterFailedOpen(): Promise<void> {
    try {
      await this.close();
    } catch {
      // Preserve the original open/schema error. `close()` clears all local
      // ownership before attempting each release, so a later close is safe.
    }
  }
}

function combineChecksum(previous: string, next: string): string {
  return createHash("sha256").update(`${previous}:${next}`).digest("hex");
}

/**
 * Query boundaries are an API contract, not an incidental DuckDB cast. Validate
 * them before opening the derived database so an invalid request has the same
 * fail-closed result whether the read model is empty, populated, or unavailable.
 */
function validateMetricQueryInput(
  input: Readonly<{
    tenantId: string;
    from: string;
    to: string;
  }>,
): void {
  if (typeof input.tenantId !== "string" || !input.tenantId.trim())
    throw new Error("PHASE10_ANALYTICS_TENANT_INVALID");
  const from = parseCanonicalUtcTimestamp(input.from);
  const to = parseCanonicalUtcTimestamp(input.to);
  if (from >= to) throw new Error("PHASE10_ANALYTICS_RANGE_INVALID");
}

function parseCanonicalUtcTimestamp(value: string): number {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  )
    throw new Error("PHASE10_ANALYTICS_TIMESTAMP_INVALID");
  const instant = Date.parse(value);
  if (!Number.isFinite(instant) || new Date(instant).toISOString() !== value)
    throw new Error("PHASE10_ANALYTICS_TIMESTAMP_INVALID");
  return instant;
}

function metricQuery(metric: AnalyticsMetricId): Readonly<{ sql: string }> {
  const ranged =
    "tenant_id = $1 AND occurred_at >= $2::TIMESTAMPTZ AND occurred_at < $3::TIMESTAMPTZ AND ($4 IS NULL OR scenario = $4)";
  switch (metric) {
    case "triage_latency":
      return {
        sql: `SELECT count(*) AS sample_count, AVG(duration_ms) AS value, quantile_cont(duration_ms, .5) AS p50, quantile_cont(duration_ms, .95) AS p95, max(duration_ms) AS max FROM (SELECT CAST(regexp_extract(status, '^duration-ms:([0-9]+)$', 1) AS BIGINT) AS duration_ms FROM analytics_facts WHERE ${ranged} AND category='trace.triage.latency')`,
      };
    case "step_duration":
      return {
        sql: `SELECT count(*) AS sample_count, AVG(duration_ms) AS value, quantile_cont(duration_ms, .5) AS p50, quantile_cont(duration_ms, .95) AS p95, max(duration_ms) AS max FROM (SELECT CAST(regexp_extract(status, '^duration-ms:([0-9]+)$', 1) AS BIGINT) AS duration_ms FROM analytics_facts WHERE ${ranged} AND category='trace.step.duration')`,
      };
    case "provider_failure_rate":
      return {
        // A provider delivery is retried in-place, so a metric sample is the
        // latest authoritative snapshot for each (delivery, attempt). This
        // preserves a failed first attempt after a later successful retry;
        // retry, exhausted and uncertain are all durable failure outcomes.
        sql: `SELECT count(*) AS sample_count, AVG(CASE WHEN status IN ('retry','exhausted','uncertain') THEN 1 ELSE 0 END) AS value FROM (SELECT * EXCLUDE (row_number, attempt) FROM (SELECT *, try_cast(regexp_extract(source_version, '^([0-9]+):', 1) AS BIGINT) AS attempt, row_number() OVER (PARTITION BY source, source_id, regexp_extract(source_version, '^([0-9]+):', 1) ORDER BY sequence DESC) AS row_number FROM analytics_facts WHERE ${ranged} AND source='provider_deliveries') WHERE row_number=1 AND attempt >= 1)`,
      };
    case "escalation_accuracy":
      return {
        sql: `SELECT count(*) AS sample_count, AVG(CASE WHEN status='passed' THEN 1 ELSE 0 END) AS value FROM analytics_facts WHERE ${ranged} AND source='eval_results' AND category='escalation_accuracy'`,
      };
    case "approval_latency":
      return {
        // approval source IDs are durable request IDs. An incident can have
        // more than one approval lifecycle, so grouping by incident would
        // silently discard requests and pair unrelated decisions.
        sql: `SELECT count(*) AS sample_count, AVG(latency_ms) AS value, quantile_cont(latency_ms, .5) AS p50, quantile_cont(latency_ms, .95) AS p95, max(latency_ms) AS max FROM (SELECT source_id, date_diff('millisecond', MIN(CASE WHEN status='pending' THEN occurred_at END), MIN(CASE WHEN status IN ('approved','rejected','expired') THEN occurred_at END)) AS latency_ms FROM analytics_facts WHERE ${ranged} AND source='approvals' GROUP BY source_id HAVING latency_ms IS NOT NULL)`,
      };
    case "guardrail_block_rate":
      return {
        sql: `SELECT count(*) AS sample_count, AVG(CASE WHEN status LIKE 'blocked:%' THEN 1 ELSE 0 END) AS value FROM analytics_facts WHERE ${ranged} AND category='guardrail.plan_attempt'`,
      };
    case "containment_execution_rate":
      return {
        // A containment attempt can first be journaled as executing and then
        // terminally as completed/blocked/failed. Count its latest state once;
        // otherwise the transitional event would dilute the action-attempt
        // denominator.
        sql: `SELECT count(*) AS sample_count, AVG(CASE WHEN status='completed:verified' THEN 1 ELSE 0 END) AS value FROM (SELECT * EXCLUDE (row_number) FROM (SELECT *, row_number() OVER (PARTITION BY source, source_id ORDER BY sequence DESC) AS row_number FROM analytics_facts WHERE ${ranged} AND category='containment.attempt') WHERE row_number=1)`,
      };
    case "audit_trace_completeness":
      return {
        sql: `SELECT count(*) AS sample_count, AVG(CASE WHEN status='present' THEN 1 ELSE 0 END) AS value FROM analytics_facts WHERE ${ranged} AND category='trace.boundary'`,
      };
  }
}
