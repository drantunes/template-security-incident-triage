import { createHmac } from "node:crypto";

import { Mastra } from "@mastra/core/mastra";
import { afterEach, describe, expect, it } from "vitest";

import {
  createIncidentFromAlert,
  createIncidentFromAlertResult,
} from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import { materializeInvestigationStart } from "../../src/db/workflow-run-operations.js";
import { loadInvestigationContext } from "../../src/mastra/steps/load-investigation-context.js";
import { baselineWorkflow } from "../../src/mastra/workflows/baseline-workflow.js";
import { incidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import { createApp } from "../../src/server.js";
import { evaluateSeverityPolicy } from "../../src/triage/policy.js";
import { readPhase8Config } from "../../src/env.js";
import { persistEvidenceItems } from "../../src/evidence/persistence.js";
import {
  persistWorkosSnapshotBeforeIncident,
  reserveWorkosObservedState,
} from "../../src/db/workos-webhook-operations.js";
import { makeAlert } from "../fixtures/domain.js";
import { makePhase2Config, phase2NowMs } from "../fixtures/phase2.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];
const testMastra = new Mastra({
  workflows: { baselineWorkflow, incidentIngestionWorkflow },
});

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

function sign(
  bytes: Uint8Array,
  secret: string,
  timestamp = String(phase2NowMs),
) {
  return `t=${timestamp},v1=${createHmac("sha256", secret)
    .update(`${timestamp}.`, "utf8")
    .update(bytes)
    .digest("hex")}`;
}

const realWorkosConfig = () =>
  readPhase8Config({
    DEMO_MODE: "staging",
    WEBHOOKS_ENABLED: "true",
    WORKOS_PROVIDER_ENABLED: "true",
    WORKOS_API_KEY: "fake-workos-api-key",
    WORKOS_WEBHOOK_SECRET: "current-workos-webhook-secret",
    WORKOS_WEBHOOK_PREVIOUS_SECRET: "previous-workos-webhook-secret",
    WORKOS_STAGING_ORGANIZATION_ID: "tenant-1",
    WORKOS_STAGING_ALLOWED_USER_IDS: "subject-1",
    WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "member,admin,viewer",
  });

describe("Phase 8 WorkOS raw webhook and InvestigationContext v2", () => {
  it("seeds the first official observation and atomically forms the next member→admin transition", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const app = await createApp({
      config: makePhase2Config(),
      phase8Config: realWorkosConfig(),
      store,
      logger: { write: () => {} },
      nowMs: () => phase2NowMs,
      mastraInstance: testMastra,
    });
    const body = new TextEncoder().encode(
      `{ "id":"evt-1", "event":"organization_membership.updated", "created_at":"2026-08-27T12:00:00.000Z", "data": { "object":"organization_membership", "id":"membership-1", "organization_id":"tenant-1", "organization_name":"Synthetic", "user_id":"subject-1", "status":"active", "directory_managed":false, "created_at":"2026-08-27T11:00:00.000Z", "updated_at":"2026-08-27T11:59:00.000Z", "custom_attributes":{}, "role":{"slug":"admin"} } }`,
    );
    const response = await app.request("/webhooks/workos", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Multiple v1 values cover current+previous rotation without changing
        // the signed bytes. The verifier must not parse/re-serialize first.
        "WorkOS-Signature": `${sign(body, "current-workos-webhook-secret")},v1=${sign(body, "previous-workos-webhook-secret").split("v1=")[1]}`,
      },
      body,
    });
    expect(response.status).toBe(202);
    expect(
      await store.execute({ sql: "SELECT count(*) AS n FROM incidents" }),
    ).toMatchObject({ rows: [{ n: 1 }] });
    await expect(
      store.execute({ sql: "SELECT count(*) AS n FROM identity_snapshots" }),
    ).resolves.toMatchObject({ rows: [{ n: 0 }] });
    await expect(
      store.execute({
        sql: "SELECT observed_role, version FROM workos_observed_memberships",
      }),
    ).resolves.toMatchObject({
      rows: [{ observed_role: "admin", version: 1 }],
    });
    await expect(
      store.execute({ sql: "SELECT count(*) AS n FROM timeline_events" }),
    ).resolves.toMatchObject({ rows: [{ n: 1 }] });
    await expect(
      store.execute({ sql: "SELECT count(*) AS n FROM outbox_events" }),
    ).resolves.toMatchObject({ rows: [{ n: 1 }] });
    store.close();
  });

  it("uses the prior official observed role for the next event without inventing actor or approval", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const app = await createApp({
      config: makePhase2Config(),
      phase8Config: realWorkosConfig(),
      store,
      logger: { write: () => {} },
      nowMs: () => phase2NowMs,
      mastraInstance: testMastra,
    });
    const send = async (
      id: string,
      role: "member" | "admin",
      updatedAt: string,
    ) => {
      const body = new TextEncoder().encode(
        JSON.stringify({
          id,
          event: "organization_membership.updated",
          created_at: updatedAt,
          data: {
            object: "organization_membership",
            id: "membership-1",
            organization_id: "tenant-1",
            organization_name: "Synthetic",
            user_id: "subject-1",
            status: "active",
            directory_managed: false,
            created_at: "2026-08-27T11:00:00.000Z",
            updated_at: updatedAt,
            custom_attributes: {},
            role: { slug: role },
          },
        }),
      );
      return app.request("/webhooks/workos", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "WorkOS-Signature": sign(body, "current-workos-webhook-secret"),
        },
        body,
      });
    };
    expect(
      (await send("evt-member", "member", "2026-08-27T12:00:00.000Z")).status,
    ).toBe(202);
    expect(
      (await send("evt-admin", "admin", "2026-08-27T12:01:00.000Z")).status,
    ).toBe(202);
    await expect(
      store.execute({ sql: "SELECT snapshot_json FROM identity_snapshots" }),
    ).resolves.toMatchObject({
      rows: [
        {
          snapshot_json:
            '{"membershipId":"membership-1","previousRole":"member","currentRole":"admin","observedCurrentRole":"admin"}',
        },
      ],
    });
    await expect(
      store.execute({
        sql: "SELECT observed_role, version FROM workos_observed_memberships",
      }),
    ).resolves.toMatchObject({
      rows: [{ observed_role: "admin", version: 2 }],
    });
    const second = await store.execute({
      sql: "SELECT canonical_json FROM alerts WHERE source_event_id = 'evt-admin'",
    });
    expect(second.rows[0]?.canonical_json).toContain('"contextVersion":2');
    expect(second.rows[0]?.canonical_json).toContain('"previousRole":"member"');
    expect(second.rows[0]?.canonical_json).toContain(
      '"actor":{"id":"workos:unknown:evt-admin","type":"unknown"}',
    );
    // A duplicate has no second snapshot/baseline advancement; a re-ordered
    // valid event remains rejected before it can change observed state.
    expect(
      (await send("evt-admin", "admin", "2026-08-27T12:01:00.000Z")).status,
    ).toBe(202);
    expect(
      (await send("evt-reordered", "member", "2026-08-27T12:00:30.000Z"))
        .status,
    ).toBe(202);
    await expect(
      store.execute({ sql: "SELECT count(*) AS n FROM identity_snapshots" }),
    ).resolves.toMatchObject({ rows: [{ n: 1 }] });
    store.close();
  });

  it("converges equal WorkOS ordering positions and audits a contradictory role/status", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const app = await createApp({
      config: makePhase2Config(),
      phase8Config: realWorkosConfig(),
      store,
      logger: { write: () => {} },
      nowMs: () => phase2NowMs,
      mastraInstance: testMastra,
    });
    const send = async (
      id: string,
      role: "member" | "admin",
      status: "active" | "inactive" = "active",
    ) => {
      const body = new TextEncoder().encode(
        JSON.stringify({
          id,
          event: "organization_membership.updated",
          created_at: "2026-08-27T12:00:00.000Z",
          data: {
            object: "organization_membership",
            id: "membership-tie",
            organization_id: "tenant-1",
            user_id: "subject-1",
            status,
            created_at: "2026-08-27T11:00:00.000Z",
            updated_at: "2026-08-27T12:00:00.000Z",
            role: { slug: role },
          },
        }),
      );
      return app.request("/webhooks/workos", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "WorkOS-Signature": sign(body, "current-workos-webhook-secret"),
        },
        body,
      });
    };
    const first = await send("tie-member-1", "member");
    expect(first.status).toBe(202);
    await expect(first.json()).resolves.toMatchObject({ duplicate: false });
    const duplicate = await send("tie-member-2", "member");
    expect(duplicate.status).toBe(202);
    await expect(duplicate.json()).resolves.toMatchObject({ duplicate: true });
    await expect(
      store.execute({
        sql: `SELECT
          (SELECT count(*) FROM incidents) AS incidents,
          (SELECT count(*) FROM alerts) AS alerts,
          (SELECT count(*) FROM timeline_events) AS timeline,
          (SELECT count(*) FROM outbox_events) AS outbox`,
      }),
    ).resolves.toMatchObject({
      rows: [{ incidents: 1, alerts: 1, timeline: 1, outbox: 1 }],
    });
    await expect(send("tie-admin", "admin")).resolves.toMatchObject({
      status: 409,
    });
    await expect(
      store.execute({
        sql: `SELECT observed_role, observed_status, version FROM workos_observed_memberships
        WHERE membership_id = 'membership-tie'`,
      }),
    ).resolves.toMatchObject({
      rows: [
        { observed_role: "member", observed_status: "active", version: 1 },
      ],
    });
    await expect(
      store.execute({
        sql: `SELECT error_code FROM dead_letter_events WHERE event_ref LIKE 'sha256:%'`,
      }),
    ).resolves.toMatchObject({
      rows: expect.arrayContaining([{ error_code: "EVENT_STATE_CONFLICT" }]),
    });
    store.close();
  });

  it("includes the allowlisted session event type in same-position canonical ordering", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const app = await createApp({
      config: makePhase2Config(),
      phase8Config: realWorkosConfig(),
      store,
      logger: { write: () => {} },
      nowMs: () => phase2NowMs,
      mastraInstance: testMastra,
    });
    const sendSession = async (
      id: string,
      ip: string,
      sessionId = "session-tie",
      event: "session.created" | "session.revoked" = "session.created",
    ) => {
      const body = new TextEncoder().encode(
        JSON.stringify({
          id,
          event,
          created_at: "2026-08-27T12:00:00.000Z",
          data: {
            object: "session",
            id: sessionId,
            organization_id: "tenant-1",
            user_id: "subject-1",
            status: "active",
            ip_address: ip,
            created_at: "2026-08-27T12:00:00.000Z",
            updated_at: "2026-08-27T12:00:00.000Z",
          },
        }),
      );
      return app.request("/webhooks/workos", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "WorkOS-Signature": sign(body, "current-workos-webhook-secret"),
        },
        body,
      });
    };
    expect((await sendSession("session-a", "8.8.8.8")).status).toBe(202);
    // Same normalized session state but a different allowlisted lifecycle
    // event is contradictory, never an idempotent retry.
    const eventTypeConflict = await sendSession(
      "session-revoked-same-state",
      "8.8.8.8",
      "session-tie",
      "session.revoked",
    );
    expect(eventTypeConflict.status).toBe(409);
    await expect(eventTypeConflict.json()).resolves.toMatchObject({
      code: "ALERT_CONFLICT",
    });
    await expect(
      store.execute({
        sql: `SELECT
          (SELECT count(*) FROM incidents) AS incidents,
          (SELECT count(*) FROM alerts) AS alerts,
          (SELECT count(*) FROM timeline_events) AS timeline,
          (SELECT count(*) FROM outbox_events) AS outbox,
          (SELECT count(*) FROM dead_letter_events
            WHERE error_code = 'EVENT_STATE_CONFLICT') AS conflicts`,
      }),
    ).resolves.toMatchObject({
      rows: [{ incidents: 1, alerts: 1, timeline: 1, outbox: 1, conflicts: 1 }],
    });
    // A different delivery ID with exactly the same provider event and
    // normalized state still converges to the first incident.
    const exactDuplicate = await sendSession(
      "session-created-duplicate",
      "8.8.8.8",
    );
    expect(exactDuplicate.status).toBe(202);
    await expect(exactDuplicate.json()).resolves.toMatchObject({
      duplicate: true,
    });
    const conflicting = await sendSession("session-b", "1.1.1.1");
    expect(conflicting.status).toBe(409);
    await expect(conflicting.json()).resolves.toMatchObject({
      code: "ALERT_CONFLICT",
    });
    await expect(
      store.execute({
        sql: `SELECT count(*) AS incidents FROM incidents`,
      }),
    ).resolves.toMatchObject({ rows: [{ incidents: 1 }] });

    const concurrent = await Promise.all([
      sendSession("session-concurrent-a", "9.9.9.9", "session-concurrent"),
      sendSession("session-concurrent-b", "9.9.9.9", "session-concurrent"),
    ]);
    expect(concurrent.map((response) => response.status)).toEqual([202, 202]);
    expect(
      (await Promise.all(concurrent.map((response) => response.json())))
        .map((body) => (body as { duplicate: boolean }).duplicate)
        .sort(),
    ).toEqual([false, true]);
    await expect(
      store.execute({
        sql: `SELECT count(*) AS alerts FROM alerts WHERE source_event_id LIKE 'session-concurrent-%'`,
      }),
    ).resolves.toMatchObject({ rows: [{ alerts: 1 }] });
    await expect(
      store.execute({
        sql: `SELECT error_code FROM dead_letter_events WHERE error_code = 'EVENT_STATE_CONFLICT'`,
      }),
    ).resolves.toMatchObject({
      rows: [
        { error_code: "EVENT_STATE_CONFLICT" },
        { error_code: "EVENT_STATE_CONFLICT" },
      ],
    });
    store.close();
  });

  it("stores member→admin snapshots with a target and CAS role", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    await createIncidentFromAlertResult(
      store,
      makeAlert({
        alertId: "alert-baseline",
        sourceEventId: "baseline",
        idempotencyKey: "idempotency-baseline",
        changes: {
          membershipId: "membership-1",
          workosEventType: "organization_membership.updated",
          observedCurrentRole: "member",
          observedStatus: "active",
        },
      }),
      { preflightAlert: reserveWorkosObservedState },
    );
    const alert = makeAlert({
      alertId: "alert-snapshot-admin",
      sourceEventId: "snapshot-member-admin",
      idempotencyKey: "idempotency-snapshot-admin",
      occurredAt: "2026-08-27T12:01:00.000Z",
      changes: {
        membershipId: "membership-1",
        workosEventType: "organization_membership.updated",
        observedCurrentRole: "admin",
        observedStatus: "active",
      },
    });
    await createIncidentFromAlertResult(store, alert, {
      preflightAlert: reserveWorkosObservedState,
      beforeIncidentWrite: persistWorkosSnapshotBeforeIncident,
    });
    await expect(
      store.execute({ sql: "SELECT snapshot_json FROM identity_snapshots" }),
    ).resolves.toMatchObject({
      rows: [
        {
          snapshot_json:
            '{"membershipId":"membership-1","previousRole":"member","currentRole":"admin","observedCurrentRole":"admin"}',
        },
      ],
    });
    store.close();
  });

  it("derives v2 roles/actor only from the validated alert and keeps v1 privilege changes manual-review", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const store = database.createStore();
    await migrateOperationalStore(store);
    const alert = makeAlert({
      kind: "unauthorized_privilege_change",
      sourceEventId: "role-event-v2",
      actor: { id: "actor-1", type: "user" },
      changes: { contextVersion: 2, previousRole: "member", nextRole: "admin" },
    });
    const incident = await createIncidentFromAlert(store, alert);
    await materializeInvestigationStart(store, {
      eventId: "workflow-run-v2",
      incidentId: incident.incidentId,
      tenantId: incident.tenantId,
      alertId: alert.alertId,
      correlationId: "correlation-v2",
    });
    const context = await loadInvestigationContext(store, {
      eventId: "workflow-run-v2",
      incidentId: incident.incidentId,
      tenantId: incident.tenantId,
      alertId: alert.alertId,
      correlationId: "correlation-v2",
      runId: "workflow-run-v2",
      duplicate: false,
    });
    expect(context).toMatchObject({
      schemaVersion: 2,
      actorId: "actor-1",
      roleChange: { previousRole: "member", currentRole: "admin" },
    });
    const evidence = await persistEvidenceItems(store, {
      context,
      source: "identity",
      provider: "workos-identity",
      facts: ["role.previous", "role.current", "actor.id"].map((factType) => ({
        semanticKey: `test-${factType}`,
        observedAt: context.occurredAt,
        factType,
        value:
          factType === "role.previous"
            ? "member"
            : factType === "role.current"
              ? "admin"
              : "actor-1",
        confidence: 1,
        confidenceProvenance: "provider" as const,
        rawPayloadRef: "protected:test-workos",
        sensitivity: "confidential" as const,
        incomplete: false,
      })),
    });
    // No local authorization record exists: an external alert cannot assert
    // change.approved, so policy fails closed instead of classifying it.
    expect(evaluateSeverityPolicy(context, evidence, 0)).toMatchObject({
      outcome: "manual-review",
      reasonCodes: expect.arrayContaining(["REQUIRED_EVIDENCE_MISSING"]),
    });
    await store.execute({
      sql: `INSERT INTO identity_role_change_authorizations(
        tenant_id, subject_id, source_event_id, actor_id, previous_role,
        current_role, approved, recorded_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
      args: [
        "tenant-1",
        "subject-1",
        "role-event-v2",
        "actor-1",
        "member",
        "admin",
        "2026-08-27T12:00:00.000Z",
      ],
    });
    const authorized = await loadInvestigationContext(store, {
      eventId: "workflow-run-v2",
      incidentId: incident.incidentId,
      tenantId: incident.tenantId,
      alertId: alert.alertId,
      correlationId: "correlation-v2",
      runId: "workflow-run-v2",
      duplicate: false,
    });
    expect(authorized.changeApproved).toBe(true);
    await store.execute({
      sql: `UPDATE identity_role_change_authorizations SET approved = 0
        WHERE tenant_id = ? AND subject_id = ? AND source_event_id = ?`,
      args: ["tenant-1", "subject-1", "role-event-v2"],
    });
    const denied = await loadInvestigationContext(store, {
      eventId: "workflow-run-v2",
      incidentId: incident.incidentId,
      tenantId: incident.tenantId,
      alertId: alert.alertId,
      correlationId: "correlation-v2",
      runId: "workflow-run-v2",
      duplicate: false,
    });
    expect(denied.changeApproved).toBe(false);
    // A local authorization bound to a different actor/role cannot leak into
    // the v2 context and therefore still fails closed.
    await store.execute({
      sql: `UPDATE identity_role_change_authorizations SET actor_id = ?
        WHERE tenant_id = ? AND subject_id = ? AND source_event_id = ?`,
      args: ["other-actor", "tenant-1", "subject-1", "role-event-v2"],
    });
    const divergent = await loadInvestigationContext(store, {
      eventId: "workflow-run-v2",
      incidentId: incident.incidentId,
      tenantId: incident.tenantId,
      alertId: alert.alertId,
      correlationId: "correlation-v2",
      runId: "workflow-run-v2",
      duplicate: false,
    });
    expect(divergent.changeApproved).toBeUndefined();
    expect(evaluateSeverityPolicy(divergent, evidence, 1)).toMatchObject({
      outcome: "manual-review",
      reasonCodes: expect.arrayContaining(["MATERIAL_CONTRADICTION"]),
    });
    store.close();
  });
});
