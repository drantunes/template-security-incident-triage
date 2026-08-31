import type { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import {
  baselineIntegrityHash,
  type DemoEvidenceBaseline,
} from "./evidence-baseline.js";
import {
  DEMO_OCCURRED_AT,
  demoId,
  type fixtureForScenario,
} from "./fixtures.js";

/** Seeds tenant-scoped authority separately from the untrusted alert payload. */
export async function seedScenarioBaseline(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  fixture: ReturnType<typeof fixtureForScenario>,
): Promise<void> {
  if (fixture.kind === "unauthorized_privilege_change") {
    await store.execute({
      sql: `INSERT OR IGNORE INTO identity_role_change_authorizations(
        tenant_id, subject_id, source_event_id, actor_id, previous_role,
        current_role, approved, recorded_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
      args: [
        fixture.tenantId,
        fixture.subjectId,
        fixture.sourceEventId,
        fixture.actor.id,
        fixture.changes.previousRole,
        fixture.changes.nextRole,
        DEMO_OCCURRED_AT,
      ],
    });
  }
  if (fixture.kind === "unknown_device_login") {
    await store.execute({
      sql: `INSERT OR IGNORE INTO authorized_devices(
        id, tenant_id, subject_id, device_id, authorized_at, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [
        demoId("authorized-device", fixture.tenantId),
        fixture.tenantId,
        fixture.subjectId,
        demoId("known-device", fixture.tenantId),
        DEMO_OCCURRED_AT,
        JSON.stringify({ source: "phase9-seed" }),
      ],
    });
  }
}

/** The fake providers read this tenant+incident-scoped authority, never fixture constants. */
export async function persistScenarioEvidenceBaseline(
  store: ReturnType<typeof createLibSqlOperationalStore>,
  fixture: ReturnType<typeof fixtureForScenario>,
  incidentId: string,
  sourceCanary?: string,
): Promise<void> {
  const baseline: DemoEvidenceBaseline = {
    version: 1,
    ...(sourceCanary ? { redactionSource: sourceCanary } : {}),
    identity: {
      actorId: fixture.actor.id,
      previousRole:
        fixture.kind === "unauthorized_privilege_change"
          ? fixture.changes.previousRole
          : "member",
      currentRole:
        fixture.kind === "unauthorized_privilege_change"
          ? fixture.changes.nextRole
          : "member",
      approved: false,
    },
    cloud: {
      allowedCountry: "US",
      abnormalHistory: false,
      countryByIp:
        fixture.kind === "disallowed_country_login"
          ? { [fixture.ip]: "CA" }
          : {},
    },
    ...(fixture.kind === "unknown_device_login"
      ? {
          device: JSON.parse(
            fixture.changes.signature,
          ) as DemoEvidenceBaseline["device"],
        }
      : {}),
  };
  const snapshot = JSON.stringify(baseline);
  await store.execute({
    sql: `INSERT INTO identity_snapshots(
      id, tenant_id, subject_id, source_event_id, snapshot_json, snapshot_ref,
      integrity_hash, schema_version, captured_at, incident_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    args: [
      demoId("evidence-baseline", fixture.sourceEventId),
      fixture.tenantId,
      fixture.subjectId,
      fixture.sourceEventId,
      snapshot,
      "protected:phase9-demo-evidence-baseline",
      baselineIntegrityHash(baseline),
      DEMO_OCCURRED_AT,
      incidentId,
    ],
  });
}
