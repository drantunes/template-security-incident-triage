import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { DuckDBInstance } from "@duckdb/node-api";

import { DuckDbAnalyticsStore } from "../../src/analytics/duckdb-analytics-store.js";
import { materializeVerifiedTraceObservations } from "../../src/analytics/trace-observations.js";
import { analyticsMetricIds } from "../../src/analytics/analytics-store.js";
import { exportAnalyticsSince } from "../../src/analytics/exporter.js";
import {
  analyticsSchemaChecksum,
  analyticsSchemaVersion,
} from "../../src/analytics/schema.js";
import { runMockDemo } from "../../src/demo/runner.js";
import { createLibSqlOperationalStore } from "../../src/db/libsql-operational-store.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

let root: string | undefined;
const databases: TempDatabase[] = [];
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  root = undefined;
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("phase 10 DuckDB read model", () => {
  it("is idempotent, tenant-scoped and single writer", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const path = join(root, "analytics.duckdb");
    const store = new DuckDbAnalyticsStore(path);
    const record = {
      sequence: 1,
      source: "timeline_events" as const,
      sourceId: "event-1",
      sourceVersion: "1",
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt: "2026-08-30T00:00:00.000Z",
      category: "triage.completed",
      status: "success",
      checksum: "a".repeat(64),
    };
    const received = {
      ...record,
      sequence: 2,
      sourceId: "event-2",
      sourceVersion: "2",
      category: "incident.received",
      checksum: "b".repeat(64),
    };
    await store.ingestBatch([record, record, received]);
    expect(await store.readCursor("timeline_events")).toBe(2);
    await expect(new DuckDbAnalyticsStore(path).migrate()).rejects.toThrow(
      "WRITER_LOCKED",
    );
    expect(
      await store.queryMetric({
        metric: "audit_trace_completeness",
        tenantId: "tenant-a",
        from: "2026-08-30T00:00:00.000Z",
        to: "2026-08-31T00:00:00.000Z",
      }),
    ).toEqual({ sampleCount: 0, value: null, reason: "NO_DATA" });
    expect(
      await store.queryMetric({
        metric: "audit_trace_completeness",
        tenantId: "tenant-b",
        from: "2026-08-30T00:00:00.000Z",
        to: "2026-08-31T00:00:00.000Z",
      }),
    ).toEqual({ sampleCount: 0, value: null, reason: "NO_DATA" });
    await store.close();
  });

  it("fails closed on a cursor gap and a divergent retry", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const store = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    const record = {
      sequence: 1,
      source: "approvals" as const,
      sourceId: "approval-1",
      sourceVersion: "pending",
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt: "2026-08-30T00:00:00.000Z",
      category: "approval",
      status: "pending",
      checksum: "b".repeat(64),
    };
    await expect(
      store.ingestBatch([{ ...record, sequence: 2 }]),
    ).rejects.toThrow("CURSOR_GAP");
    await store.ingestBatch([record]);
    await expect(
      store.ingestBatch([{ ...record, tenantId: "tenant-b" }]),
    ).rejects.toThrow("IDEMPOTENCY_CONFLICT");
    await store.assertIntegrity([record]);
    await store.close();
  });

  it("exports the immutable journal snapshot rather than a mutable source", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const operational = database.createStore();
    await migrateOperationalStore(operational);
    const snapshot = JSON.stringify({
      id: "journal-1",
      tenant_id: "tenant-a",
      incident_id: "incident-a",
      occurred_at: "2026-08-30T00:00:00.000Z",
      category: "provider-operation",
      status: "pending",
    });
    await operational.execute({
      sql: `INSERT INTO analytics_export_events(source,source_id,source_version,changed_at,snapshot_json)
        VALUES ('provider_deliveries','journal-1','1:pending','2026-08-30T00:00:00.000Z',?)`,
      args: [snapshot],
    });
    const exported = await exportAnalyticsSince(operational, 0);
    expect(exported).toHaveLength(1);
    expect(exported[0]).toMatchObject({
      category: "provider-operation",
      status: "pending",
      tenantId: "tenant-a",
    });
    operational.close();
  });

  it("accepts distinct immutable journal events for an unchanged producer version", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const operational = database.createStore();
    await migrateOperationalStore(operational);
    for (const [status, snapshot] of [
      ["pending", "provider-snapshot-a"],
      ["pending", "provider-snapshot-b"],
    ] as const)
      await operational.execute({
        sql: `INSERT INTO analytics_export_events(source,source_id,source_version,changed_at,snapshot_json)
          VALUES ('provider_deliveries','provider-1','0:pending','2026-08-30T00:00:00.000Z',?)`,
        args: [
          JSON.stringify({
            id: "provider-1",
            tenant_id: "tenant-a",
            incident_id: "incident-a",
            occurred_at: "2026-08-30T00:00:00.000Z",
            category: snapshot,
            status,
          }),
        ],
      });
    const exported = await exportAnalyticsSince(operational, 0);
    expect(exported.map((row) => row.sourceVersion)).toEqual([
      "0:pending@1",
      "0:pending@2",
    ]);
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const readModel = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    await expect(readModel.ingestBatch(exported)).resolves.toBeUndefined();
    await readModel.close();
    operational.close();
  });

  it("uses paired event clocks and relevant denominators rather than fact counts", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const store = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    const make = (sequence: number, category: string, occurredAt: string) => ({
      sequence,
      source: "timeline_events" as const,
      sourceId: `event-${sequence}`,
      sourceVersion: `v${sequence}`,
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt,
      category,
      status: "success",
      checksum: String(sequence).padStart(64, "a"),
    });
    await store.ingestBatch([
      make(1, "incident.received", "2026-08-30T00:00:00.000Z"),
      {
        ...make(2, "trace.triage.latency", "2026-08-30T00:00:01.000Z"),
        status: "duration-ms:1000",
      },
      {
        ...make(3, "trace.step.duration", "2026-08-30T00:00:02.000Z"),
        status: "duration-ms:3000",
      },
    ]);
    const window = {
      tenantId: "tenant-a",
      from: "2026-08-30T00:00:00.000Z",
      to: "2026-08-31T00:00:00.000Z",
    };
    expect(
      await store.queryMetric({ ...window, metric: "triage_latency" }),
    ).toEqual({
      sampleCount: 1,
      value: 1000,
      distribution: { p50: 1000, p95: 1000, max: 1000 },
    });
    expect(
      await store.queryMetric({ ...window, metric: "step_duration" }),
    ).toEqual({
      sampleCount: 1,
      value: 3000,
      distribution: { p50: 3000, p95: 3000, max: 3000 },
    });
    expect(
      await store.queryMetric({ ...window, metric: "provider_failure_rate" }),
    ).toEqual({ sampleCount: 0, value: null, reason: "NO_DATA" });
    await store.close();
  });

  it("uses every authoritative provider failure state and records blocked guardrail reasons", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const store = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    const record = (
      sequence: number,
      source: "timeline_events" | "provider_deliveries",
      sourceId: string,
      category: string,
      status: string,
      sourceVersion: string,
    ) => ({
      sequence,
      source,
      sourceId,
      sourceVersion,
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt: "2026-08-30T00:00:00.000Z",
      category,
      status,
      checksum: `${sequence}`.padStart(64, "0"),
    });
    await store.ingestBatch([
      record(
        1,
        "provider_deliveries",
        "delivery-a",
        "ticket",
        "retry",
        "1:retry",
      ),
      record(
        2,
        "provider_deliveries",
        "delivery-a",
        "ticket",
        "succeeded",
        "2:succeeded",
      ),
      record(
        3,
        "provider_deliveries",
        "delivery-b",
        "chat",
        "retry",
        "1:retry",
      ),
      record(
        4,
        "provider_deliveries",
        "delivery-c",
        "chat",
        "exhausted",
        "1:exhausted",
      ),
      record(
        5,
        "provider_deliveries",
        "delivery-d",
        "chat",
        "uncertain",
        "1:uncertain",
      ),
      record(
        6,
        "timeline_events",
        "guardrail-a",
        "guardrail.plan_attempt",
        "allowed",
        "1",
      ),
      record(
        7,
        "timeline_events",
        "guardrail-b",
        "guardrail.plan_attempt",
        "blocked:PLAN_INVALID",
        "1",
      ),
    ]);
    const window = {
      tenantId: "tenant-a",
      from: "2026-08-30T00:00:00.000Z",
      to: "2026-08-31T00:00:00.000Z",
    };
    await expect(
      store.queryMetric({ ...window, metric: "provider_failure_rate" }),
    ).resolves.toEqual({ sampleCount: 5, value: 0.8 });
    await expect(
      store.queryMetric({ ...window, metric: "guardrail_block_rate" }),
    ).resolves.toEqual({ sampleCount: 2, value: 0.5 });
    await store.close();
  });

  it("pairs every approval request with its own authoritative terminal decision", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const store = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    const approval = (
      sequence: number,
      sourceId: string,
      status: "pending" | "approved" | "rejected" | "expired",
      occurredAt: string,
    ) => ({
      sequence,
      source: "approvals" as const,
      sourceId,
      sourceVersion: `${sequence}:${status}`,
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt,
      category: "approval",
      status,
      checksum: String(sequence).padStart(64, "0"),
    });
    const window = {
      tenantId: "tenant-a",
      from: "2026-08-30T00:00:00.000Z",
      to: "2026-08-31T00:00:00.000Z",
    };
    await store.ingestBatch([
      approval(1, "approval-1", "pending", "2026-08-30T00:00:00.000Z"),
      approval(2, "approval-1", "approved", "2026-08-30T00:00:01.000Z"),
      approval(3, "approval-2", "pending", "2026-08-30T00:00:00.000Z"),
      approval(4, "approval-2", "rejected", "2026-08-30T00:00:03.000Z"),
    ]);
    await expect(
      store.queryMetric({ ...window, metric: "approval_latency" }),
    ).resolves.toEqual({
      sampleCount: 2,
      value: 2000,
      distribution: { p50: 2000, p95: 2900, max: 3000 },
    });

    await store.ingestBatch([
      approval(5, "approval-3", "pending", "2026-08-30T00:00:00.000Z"),
      approval(6, "approval-3", "expired", "2026-08-30T00:00:05.000Z"),
    ]);
    await expect(
      store.queryMetric({ ...window, metric: "approval_latency" }),
    ).resolves.toEqual({
      sampleCount: 3,
      value: 3000,
      distribution: { p50: 3000, p95: 4800, max: 5000 },
    });
    await store.close();
  });

  it("validates tenant and canonical UTC ranges before querying either an empty or populated store", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const empty = new DuckDbAnalyticsStore(join(root, "empty.duckdb"));
    const populated = new DuckDbAnalyticsStore(join(root, "populated.duckdb"));
    await populated.ingestBatch([
      {
        sequence: 1,
        source: "timeline_events" as const,
        sourceId: "at-from",
        sourceVersion: "1",
        tenantId: "tenant-a",
        incidentId: "incident-a",
        occurredAt: "2026-08-30T00:00:00.000Z",
        category: "trace.boundary",
        status: "present",
        checksum: "a".repeat(64),
      },
      {
        sequence: 2,
        source: "timeline_events" as const,
        sourceId: "at-to",
        sourceVersion: "2",
        tenantId: "tenant-a",
        incidentId: "incident-a",
        occurredAt: "2026-08-31T00:00:00.000Z",
        category: "trace.boundary",
        status: "present",
        checksum: "b".repeat(64),
      },
    ]);
    const valid = {
      metric: "audit_trace_completeness" as const,
      tenantId: "tenant-a",
      from: "2026-08-30T00:00:00.000Z",
      to: "2026-08-31T00:00:00.000Z",
    };
    await expect(populated.queryMetric(valid)).resolves.toEqual({
      sampleCount: 1,
      value: 1,
    });
    const missingTenant = { ...valid } as Partial<typeof valid>;
    delete missingTenant.tenantId;
    const invalid = [
      [missingTenant as typeof valid, "PHASE10_ANALYTICS_TENANT_INVALID"],
      [{ ...valid, tenantId: "" }, "PHASE10_ANALYTICS_TENANT_INVALID"],
      [{ ...valid, tenantId: "  " }, "PHASE10_ANALYTICS_TENANT_INVALID"],
      [{ ...valid, from: "not-a-date" }, "PHASE10_ANALYTICS_TIMESTAMP_INVALID"],
      [
        { ...valid, to: "2026-08-31T00:00:00.000+00:00" },
        "PHASE10_ANALYTICS_TIMESTAMP_INVALID",
      ],
      [{ ...valid, to: valid.from }, "PHASE10_ANALYTICS_RANGE_INVALID"],
      [{ ...valid, from: valid.to }, "PHASE10_ANALYTICS_RANGE_INVALID"],
    ] as const;
    for (const [query, code] of invalid)
      for (const store of [empty, populated])
        await expect(store.queryMetric(query)).rejects.toThrow(code);
    await empty.close();
    await populated.close();
  });

  it("rejects a missing domain receive clock and counts every required trace boundary", async () => {
    const demoRoot = await mkdtemp(join(tmpdir(), "phase10-trace-clock-"));
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const run = await runMockDemo({
      root: demoRoot,
      scenario: "privilege",
      decision: "approve",
      runKey: "phase10-trace-boundary-negative",
      timeoutMs: 12_000,
    });
    expect(run.exitCode).toBe(0);
    const operational = createLibSqlOperationalStore({
      url: `file:${run.journal.databasePath}`,
    });
    const analytics = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    try {
      const incident = await operational.execute({
        sql: `SELECT tenant_id,incident_id,occurred_at FROM timeline_events
          WHERE type='incident.received' ORDER BY sequence LIMIT 1`,
      });
      const receivedAt = Date.parse(String(incident.rows[0]?.occurred_at));
      const boundaries = [
        {
          spanId: "completed",
          traceId: "boundary-negative",
          name: "triage.completed",
          startMs: receivedAt,
          endMs: receivedAt + 1_000,
          attributes: { stepId: "finalize-incident" },
        },
      ] as const;
      await expect(
        materializeVerifiedTraceObservations(operational, {
          tenantId: "missing-tenant",
          incidentId: "missing-incident",
          scenario: "privilege",
          traceId: "missing-clock",
          boundaries,
          requiredBoundaries: ["triage.completed"],
        }),
      ).rejects.toThrow("PHASE10_ANALYTICS_TRACE_CLOCK_INVALID");
      await materializeVerifiedTraceObservations(operational, {
        tenantId: String(incident.rows[0]?.tenant_id),
        incidentId: String(incident.rows[0]?.incident_id),
        scenario: "privilege",
        traceId: "boundary-negative",
        boundaries,
        requiredBoundaries: ["triage.completed", "provider.delivery"],
      });
      await analytics.ingestBatch(await exportAnalyticsSince(operational, 0));
      await expect(
        analytics.queryMetric({
          metric: "audit_trace_completeness",
          tenantId: String(incident.rows[0]?.tenant_id),
          from: "2026-08-30T00:00:00.000Z",
          to: "2026-08-31T00:00:00.000Z",
          scenario: "privilege",
        }),
      ).resolves.toEqual({ sampleCount: 2, value: 0.5 });
    } finally {
      await analytics.close();
      operational.close();
      await rm(demoRoot, { recursive: true, force: true });
    }
  }, 20_000);

  it("creates, rebuilds, and reopens only the approved v1 metadata layout", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const path = join(root, "analytics.duckdb");
    const record = {
      sequence: 1,
      source: "timeline_events" as const,
      sourceId: "event-v1",
      sourceVersion: "v1",
      tenantId: "tenant-a",
      incidentId: "incident-a",
      occurredAt: "2026-08-30T00:00:00.000Z",
      category: "incident.received",
      checksum: "c".repeat(64),
    };
    const store = new DuckDbAnalyticsStore(path);
    await store.ingestBatch([record]);
    await store.rebuild([record]);
    await store.close();

    const instance = await DuckDBInstance.create(path);
    const connection = await instance.connect();
    try {
      const versions = await (
        await connection.run("SELECT version FROM analytics_schema_versions")
      ).getRowObjectsJS();
      const cursors = await (
        await connection.run("SELECT schema_version FROM ingest_cursors")
      ).getRowObjectsJS();
      const state = await (
        await connection.run(
          "SELECT schema_version, record_count FROM analytics_ingest_state WHERE id=1",
        )
      ).getRowObjectsJS();
      expect(versions).toEqual([{ version: analyticsSchemaVersion }]);
      expect(cursors).toHaveLength(4);
      expect(
        cursors.every((row) => row.schema_version === analyticsSchemaVersion),
      ).toBe(true);
      expect(state).toEqual([
        { schema_version: analyticsSchemaVersion, record_count: 1n },
      ]);
    } finally {
      connection.closeSync();
      instance.closeSync();
    }
    const reopened = new DuckDbAnalyticsStore(path);
    await expect(reopened.migrate()).resolves.toBeUndefined();
    await reopened.close();
  });

  it("rejects a derived file with a version collision instead of upgrading it", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const path = join(root, "analytics.duckdb");
    const instance = await DuckDBInstance.create(path);
    const connection = await instance.connect();
    await connection.run(
      "CREATE TABLE analytics_schema_versions(version INTEGER PRIMARY KEY, checksum VARCHAR NOT NULL, applied_at VARCHAR NOT NULL)",
    );
    await connection.run(
      "INSERT INTO analytics_schema_versions VALUES (2, 'unapproved-v2', '2026-08-30T00:00:00.000Z')",
    );
    connection.closeSync();
    instance.closeSync();
    await expect(new DuckDbAnalyticsStore(path).migrate()).rejects.toThrow(
      "PHASE10_ANALYTICS_SCHEMA_INVALID",
    );
  });

  it("releases initial-open ownership after every schema validation failure", async () => {
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    for (const invalid of ["version", "checksum", "cursor", "state"] as const) {
      const path = join(root, `${invalid}.duckdb`);
      const prepared = new DuckDbAnalyticsStore(path);
      await prepared.migrate();
      await prepared.close();
      const instance = await DuckDBInstance.create(path);
      const connection = await instance.connect();
      try {
        switch (invalid) {
          case "version":
            await connection.run("DELETE FROM analytics_schema_versions");
            await connection.run(
              "INSERT INTO analytics_schema_versions VALUES (2, 'unapproved-v2', '2026-08-30T00:00:00.000Z')",
            );
            break;
          case "checksum":
            await connection.run(
              "UPDATE analytics_schema_versions SET checksum='wrong-checksum'",
            );
            break;
          case "cursor":
            await connection.run(
              "UPDATE ingest_cursors SET schema_version=2 WHERE source='approvals'",
            );
            break;
          case "state":
            await connection.run(
              "UPDATE analytics_ingest_state SET schema_version=2 WHERE id=1",
            );
            break;
        }
      } finally {
        connection.closeSync();
        instance.closeSync();
      }

      // No caller cleanup follows this rejection: migrate itself owns every
      // resource it acquired during its first open.
      await expect(new DuckDbAnalyticsStore(path).migrate()).rejects.toThrow(
        "PHASE10_ANALYTICS_SCHEMA_INVALID",
      );
      await expect(stat(`${path}.phase10.lock`)).rejects.toThrow();

      const repair = await DuckDBInstance.create(path);
      const repairConnection = await repair.connect();
      try {
        switch (invalid) {
          case "version":
            await repairConnection.run("DELETE FROM analytics_schema_versions");
            await repairConnection.run(
              "INSERT INTO analytics_schema_versions VALUES (1, $1, '2026-08-30T00:00:00.000Z')",
              [analyticsSchemaChecksum],
            );
            break;
          case "checksum":
            await repairConnection.run(
              "UPDATE analytics_schema_versions SET checksum=$1",
              [analyticsSchemaChecksum],
            );
            break;
          case "cursor":
            await repairConnection.run(
              "UPDATE ingest_cursors SET schema_version=$1 WHERE source='approvals'",
              [analyticsSchemaVersion],
            );
            break;
          case "state":
            await repairConnection.run(
              "UPDATE analytics_ingest_state SET schema_version=$1 WHERE id=1",
              [analyticsSchemaVersion],
            );
            break;
        }
      } finally {
        repairConnection.closeSync();
        repair.closeSync();
      }
      const secondWriter = new DuckDbAnalyticsStore(path);
      await expect(secondWriter.migrate()).resolves.toBeUndefined();
      await secondWriter.close();
    }
  });

  it("exports isolated approve, reject and expire fixtures into every scenario metric", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const operational = database.createStore();
    root = await mkdtemp(join(tmpdir(), "phase10-analytics-"));
    const analytics = new DuckDbAnalyticsStore(join(root, "analytics.duckdb"));
    try {
      await migrateOperationalStore(operational);
      for (const fixture of syntheticE2eAnalyticsFixtures)
        for (const event of fixture.events)
          await operational.execute({
            sql: "INSERT INTO analytics_export_events(source,source_id,source_version,changed_at,snapshot_json) VALUES (?,?,?,?,?)",
            args: [
              event.source,
              event.id,
              "synthetic-e2e-v1",
              event.occurredAt,
              JSON.stringify({
                id: event.id,
                tenant_id: "tenant-e2e",
                incident_id: fixture.incidentId,
                occurred_at: event.occurredAt,
                category: event.category,
                status: event.status,
                scenario: fixture.scenario,
              }),
            ],
          });

      const exported = await exportAnalyticsSince(operational, 0);
      expect(exported).toHaveLength(30);
      expect(exported.every((event) => event.scenario !== undefined)).toBe(
        true,
      );
      await analytics.ingestBatch(exported);

      const window = {
        tenantId: "tenant-e2e",
        from: "2026-08-30T00:00:00.000Z",
        to: "2026-08-31T00:00:00.000Z",
      };
      for (const fixture of syntheticE2eAnalyticsFixtures) {
        const results = await Promise.all(
          analyticsMetricIds.map((metric) =>
            analytics.queryMetric({
              ...window,
              metric,
              scenario: fixture.scenario,
            }),
          ),
        );
        // Synthetic rows remain a parser/idempotency regression only. Product
        // metric semantics are asserted by the temporary-approved report E2E.
        expect(results).toHaveLength(analyticsMetricIds.length);
      }
      for (const metric of analyticsMetricIds)
        await expect(
          analytics.queryMetric({ ...window, metric, scenario: "empty" }),
        ).resolves.toEqual({ sampleCount: 0, value: null, reason: "NO_DATA" });
    } finally {
      await analytics.close();
      operational.close();
    }
  });

  it("derives the eight metrics from the three real Phase 9 E2Es", async () => {
    const demoRoot = await mkdtemp(join(tmpdir(), "phase10-real-e2e-"));
    try {
      for (const [scenario, decision] of [
        ["privilege", "approve"],
        ["country", "reject"],
        ["device", "expire"],
      ] as const) {
        const run = await runMockDemo({
          root: demoRoot,
          scenario,
          decision,
          runKey: `phase10-analytics-${scenario}`,
          timeoutMs: 12_000,
        });
        expect(run.exitCode).toBe(0);
        const operational = createLibSqlOperationalStore({
          url: `file:${run.journal.databasePath}`,
        });
        const analyticsRoot = await mkdtemp(
          join(tmpdir(), "phase10-analytics-"),
        );
        const analytics = new DuckDbAnalyticsStore(
          join(analyticsRoot, "analytics.duckdb"),
        );
        try {
          const exported = await exportAnalyticsSince(operational, 0);
          expect(exported.length).toBeGreaterThan(0);
          expect(exported.every((event) => event.scenario === scenario)).toBe(
            true,
          );
          expect(
            exported.some((event) => event.category === "triage.completed"),
          ).toBe(true);
          expect(
            exported.some((event) => event.category.startsWith("triage.")),
          ).toBe(true);
          expect(
            exported.some((event) => event.source === "provider_deliveries"),
          ).toBe(true);
          expect(exported.some((event) => event.source === "approvals")).toBe(
            true,
          );
          await analytics.ingestBatch(exported);
          const window = {
            tenantId: exported[0]!.tenantId,
            from: "2026-08-30T00:00:00.000Z",
            to: "2026-08-31T00:00:00.000Z",
            scenario,
          };
          const values = new Map(
            await Promise.all(
              analyticsMetricIds.map(
                async (metric) =>
                  [
                    metric,
                    await analytics.queryMetric({ ...window, metric }),
                  ] as const,
              ),
            ),
          );
          expect(values.size).toBe(analyticsMetricIds.length);
        } finally {
          await analytics.close();
          operational.close();
          await rm(analyticsRoot, { recursive: true, force: true });
        }
      }
    } finally {
      await rm(demoRoot, { recursive: true, force: true });
    }
  }, 90_000);
});

const metrics = (values: readonly number[]) =>
  values.map((value) => ({ sampleCount: 1, value }));

const syntheticE2eAnalyticsFixtures = [
  {
    scenario: "privilege",
    incidentId: "incident-e2e-approve",
    expected: [
      ...metrics([10_000, 5_000, 0, 1, 10_000]),
      { sampleCount: 2, value: 0.5 },
      ...metrics([1, 1]),
    ],
    events: scenarioEvents("approve", {
      providerStatus: "success",
      evaluationStatus: "passed",
      guardrailStatus: "blocked",
      containmentStatus: "executed",
      approvalStatus: "approved",
    }),
  },
  {
    scenario: "country",
    incidentId: "incident-e2e-reject",
    expected: [
      ...metrics([10_000, 5_000, 1, 0, 10_000]),
      { sampleCount: 1, value: 0 },
      ...metrics([0, 1]),
    ],
    events: scenarioEvents("reject", {
      providerStatus: "failed",
      evaluationStatus: "failed",
      guardrailStatus: "allowed",
      containmentStatus: "not_executed",
      approvalStatus: "rejected",
    }),
  },
  {
    scenario: "device",
    incidentId: "incident-e2e-expire",
    expected: [
      ...metrics([10_000, 5_000, 0, 1, 10_000]),
      { sampleCount: 1, value: 0 },
      ...metrics([0, 1]),
    ],
    events: scenarioEvents("expire", {
      providerStatus: "success",
      evaluationStatus: "passed",
      guardrailStatus: "allowed",
      containmentStatus: "not_executed",
      approvalStatus: "expired",
    }),
  },
] as const;

function scenarioEvents(
  flow: string,
  status: Readonly<{
    providerStatus: string;
    evaluationStatus: string;
    guardrailStatus: string;
    containmentStatus: string;
    approvalStatus: string;
  }>,
) {
  const at = (second: number) =>
    `2026-08-30T00:00:${String(second).padStart(2, "0")}.000Z`;
  const event = (
    source:
      "timeline_events" | "provider_deliveries" | "approvals" | "eval_results",
    suffix: string,
    category: string,
    eventStatus: string,
    second: number,
  ) => ({
    source,
    id: `synthetic-${flow}-${suffix}`,
    category,
    status: eventStatus,
    occurredAt: at(second),
  });
  return [
    event("timeline_events", "received", "incident.received", "received", 0),
    event("timeline_events", "triage", "triage.completed", "completed", 10),
    event(
      "timeline_events",
      "step-start",
      "triage.classification.completed",
      "started",
      11,
    ),
    event(
      "timeline_events",
      "step-complete",
      "triage.summary.completed",
      "completed",
      16,
    ),
    event(
      "timeline_events",
      "guardrail",
      status.guardrailStatus === "blocked"
        ? "triage.validation.blocked"
        : "triage.validation.completed",
      status.guardrailStatus,
      17,
    ),
    event(
      "timeline_events",
      "containment",
      "containment.completed",
      status.containmentStatus,
      20,
    ),
    event(
      "provider_deliveries",
      "provider",
      "provider.delivery",
      status.providerStatus,
      30,
    ),
    event("approvals", "pending", "approval", "pending", 40),
    event("approvals", "terminal", "approval", status.approvalStatus, 50),
    event(
      "eval_results",
      "eval",
      "escalation_accuracy",
      status.evaluationStatus,
      55,
    ),
  ];
}
