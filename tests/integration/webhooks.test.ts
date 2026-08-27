import { afterEach, describe, expect, it } from "vitest";
import { Mastra } from "@mastra/core/mastra";

import { migrateOperationalStore } from "../../src/db/migrate.js";
import type { OperationalStore } from "../../src/db/operational-store.js";
import type { LogRecord } from "../../src/logging.js";
import { createApp } from "../../src/server.js";
import { baselineWorkflow } from "../../src/mastra/workflows/baseline-workflow.js";
import { incidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import {
  alertSecret,
  makeDemoWebhook,
  makePhase2Config,
  phase2NowMs,
  signBody,
  workosSecret,
} from "../fixtures/phase2.js";
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

async function setup(maxBodyBytes = 65_536, mastraMaxBodyBytes = 1_048_576) {
  const database = await createTempDatabase();
  databases.push(database);
  const store = database.createStore();
  await migrateOperationalStore(store);
  const logs: LogRecord[] = [];
  const app = await createApp({
    config: makePhase2Config({
      webhookMaxBodyBytes: maxBodyBytes,
      mastraMaxBodyBytes,
    }),
    store,
    logger: { write: (record) => logs.push(record) },
    createRequestId: () => "request-1",
    nowMs: () => phase2NowMs,
    mastraInstance: testMastra,
  });
  return { app, store, logs };
}

async function postAlert(
  app: Awaited<ReturnType<typeof createApp>>,
  payload: unknown,
  options: Readonly<{
    signature?: string;
    contentType?: string;
    rawBody?: string;
  }> = {},
) {
  const body = options.rawBody ?? JSON.stringify(payload);
  return app.request("/webhooks/alerts", {
    method: "POST",
    headers: {
      "Content-Type": options.contentType ?? "application/json",
      "X-Alert-Signature": options.signature ?? signBody(body),
      "X-Correlation-ID": "correlation-1",
    },
    body,
  });
}

async function postWorkOs(
  app: Awaited<ReturnType<typeof createApp>>,
  payload: unknown,
) {
  const body = JSON.stringify(payload);
  return app.request("/webhooks/workos", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "WorkOS-Signature": signBody(body, workosSecret),
    },
    body,
  });
}

async function counts(store: OperationalStore) {
  const result = await store.execute({
    sql: `SELECT
      (SELECT count(*) FROM incidents) AS incidents,
      (SELECT count(*) FROM alerts) AS alerts,
      (SELECT count(*) FROM timeline_events) AS timeline,
      (SELECT count(*) FROM outbox_events) AS outbox,
      (SELECT count(*) FROM workflow_runs) AS runs,
      (SELECT count(*) FROM dead_letter_events) AS dead_letters`,
  });
  return result.rows[0];
}

describe("signed webhook ingestion", () => {
  it("commits incident, alert, timeline and outbox before returning 202", async () => {
    const { app, store, logs } = await setup();
    try {
      const response = await postAlert(app, makeDemoWebhook());
      expect(response.status).toBe(202);
      expect(await response.json()).toEqual({
        accepted: true,
        duplicate: false,
        incidentId: expect.any(String),
        requestId: "request-1",
        correlationId: "correlation-1",
      });
      expect(await counts(store)).toEqual({
        incidents: 1,
        alerts: 1,
        timeline: 1,
        outbox: 1,
        runs: 0,
        dead_letters: 0,
      });
      expect(logs).toContainEqual(
        expect.objectContaining({
          event: "webhook.ingest.committed",
          requestId: "request-1",
          correlationId: "correlation-1",
        }),
      );
    } finally {
      store.close();
    }
  });

  it("deduplicates equivalent retries and rejects divergent retries", async () => {
    const { app, store } = await setup();
    try {
      expect((await postAlert(app, makeDemoWebhook())).status).toBe(202);
      const duplicate = await postAlert(app, makeDemoWebhook());
      expect(duplicate.status).toBe(202);
      expect(await duplicate.json()).toMatchObject({ duplicate: true });
      const conflict = await postAlert(
        app,
        makeDemoWebhook({ kind: "unknown_device_login" }),
      );
      expect(conflict.status).toBe(409);
      expect(await conflict.json()).toMatchObject({
        code: "ALERT_CONFLICT",
        retryable: false,
      });
      expect(await counts(store)).toMatchObject({
        incidents: 1,
        alerts: 1,
        timeline: 1,
        outbox: 1,
      });
    } finally {
      store.close();
    }
  });

  it("deduplicates a semantically equivalent retry with different JSON bytes", async () => {
    const { app, store } = await setup();
    try {
      const payload = makeDemoWebhook();
      expect((await postAlert(app, payload)).status).toBe(202);
      const prettyBody = JSON.stringify(payload, null, 2);
      const duplicate = await postAlert(app, payload, { rawBody: prettyBody });
      expect(duplicate.status).toBe(202);
      expect(await duplicate.json()).toMatchObject({ duplicate: true });
      expect(await counts(store)).toMatchObject({
        incidents: 1,
        alerts: 1,
        timeline: 1,
        outbox: 1,
      });
    } finally {
      store.close();
    }
  });

  it("rejects a WorkOS retry whose required actor identity diverges", async () => {
    const { app, store } = await setup();
    const payload = {
      id: "event-country-actor-conflict",
      event: "mock.session.country_login",
      created_at: "2026-08-27T12:00:00.000Z",
      data: {
        tenant_id: "tenant-1",
        subject_id: "subject-1",
        actor_id: "actor-A",
        session_id: "session-1",
        ip: "203.0.113.10",
      },
    };
    try {
      expect((await postWorkOs(app, payload)).status).toBe(202);
      const conflict = await postWorkOs(app, {
        ...payload,
        data: { ...payload.data, actor_id: "actor-B" },
      });
      expect(conflict.status).toBe(409);
      expect(await conflict.json()).toMatchObject({ code: "ALERT_CONFLICT" });
      expect(await counts(store)).toMatchObject({
        incidents: 1,
        alerts: 1,
        timeline: 1,
        outbox: 1,
      });
    } finally {
      store.close();
    }
  });

  it("rejects content type, oversized body and invalid signature before persistence", async () => {
    const { app, store, logs } = await setup(1_024);
    try {
      const wrongType = await postAlert(app, makeDemoWebhook(), {
        contentType: "application/json; charset=utf-8",
      });
      expect(wrongType.status).toBe(415);
      const body = JSON.stringify(
        makeDemoWebhook({ padding: "x".repeat(2_000) }),
      );
      const oversized = await postAlert(app, {}, { rawBody: body });
      expect(oversized.status).toBe(413);
      const invalid = await postAlert(
        app,
        { canary: "secret-payload-canary" },
        {
          signature: `t=${phase2NowMs},v1=${"0".repeat(64)}`,
        },
      );
      expect(invalid.status).toBe(401);
      expect(await counts(store)).toEqual({
        incidents: 0,
        alerts: 0,
        timeline: 0,
        outbox: 0,
        runs: 0,
        dead_letters: 0,
      });
      expect(JSON.stringify(logs)).not.toContain("secret-payload-canary");
      expect(JSON.stringify(logs)).not.toContain(alertSecret);
      expect(JSON.stringify(logs)).not.toContain("v1=");
    } finally {
      store.close();
    }
  });

  it("does not parse invalid JSON when the signature is invalid", async () => {
    const { app, store } = await setup();
    try {
      const response = await postAlert(
        app,
        {},
        {
          rawBody: "{invalid-json",
          signature: `t=${phase2NowMs},v1=${"0".repeat(64)}`,
        },
      );
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({
        code: "SIGNATURE_INVALID",
      });
      expect(await counts(store)).toMatchObject({
        incidents: 0,
        dead_letters: 0,
      });
    } finally {
      store.close();
    }
  });

  it("maps signed invalid UTF-8 to a redacted schema error", async () => {
    const { app, store } = await setup();
    try {
      const body = new Uint8Array([0xff, 0xfe]);
      const response = await app.request("/webhooks/alerts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Alert-Signature": signBody(body),
        },
        body,
      });
      expect(response.status).toBe(422);
      expect(await response.json()).toMatchObject({ code: "PAYLOAD_INVALID" });
      expect(await counts(store)).toMatchObject({
        incidents: 0,
        dead_letters: 0,
      });
    } finally {
      store.close();
    }
  });

  it("dead-letters authenticated unknown and out-of-order events without a run", async () => {
    const { app, store } = await setup();
    try {
      expect(
        (
          await postAlert(
            app,
            makeDemoWebhook({
              sourceEventId: "newer",
              occurredAt: "2026-08-27T11:59:30.000Z",
            }),
          )
        ).status,
      ).toBe(202);
      const older = await postAlert(
        app,
        makeDemoWebhook({
          sourceEventId: "older",
          occurredAt: "2026-08-27T11:58:00.000Z",
        }),
      );
      expect(await older.json()).toMatchObject({
        accepted: false,
        disposition: "dead_lettered",
        reasonCode: "EVENT_OUT_OF_ORDER",
      });
      const workosBody = JSON.stringify({
        id: "event-unknown",
        event: "mock.unknown",
        created_at: "2026-08-27T12:00:00.000Z",
        data: {},
      });
      const unknown = await app.request("/webhooks/workos", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "WorkOS-Signature": signBody(workosBody, workosSecret),
        },
        body: workosBody,
      });
      expect(unknown.status).toBe(202);
      expect(await unknown.json()).toMatchObject({
        reasonCode: "EVENT_UNKNOWN",
      });
      expect(await counts(store)).toMatchObject({
        incidents: 1,
        alerts: 1,
        runs: 0,
        dead_letters: 2,
      });
    } finally {
      store.close();
    }
  });

  it("accepts an older alert from a different event-kind stream", async () => {
    const { app, store } = await setup();
    try {
      expect(
        (
          await postAlert(
            app,
            makeDemoWebhook({
              sourceEventId: "newer-privilege",
              occurredAt: "2026-08-27T11:59:30.000Z",
            }),
          )
        ).status,
      ).toBe(202);
      const olderLogin = await postAlert(
        app,
        makeDemoWebhook({
          sourceEventId: "older-login",
          kind: "disallowed_country_login",
          occurredAt: "2026-08-27T11:59:00.000Z",
          changes: {},
          sessionId: "session-1",
          ip: "203.0.113.10",
        }),
      );
      expect(olderLogin.status).toBe(202);
      expect(await olderLogin.json()).toMatchObject({
        accepted: true,
        duplicate: false,
      });
      expect(await counts(store)).toMatchObject({
        incidents: 2,
        alerts: 2,
        dead_letters: 0,
      });
    } finally {
      store.close();
    }
  });

  it("atomically rejects an older same-kind alert when a newer alert commits during a controlled race", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const olderStore = database.createStore();
    const newerStore = database.createStore();
    await migrateOperationalStore(olderStore);
    let releaseOlder = () => {};
    const olderMayContinue = new Promise<void>((resolve) => {
      releaseOlder = resolve;
    });
    let signalOlderTransaction = () => {};
    const olderTransactionStarted = new Promise<void>((resolve) => {
      signalOlderTransaction = resolve;
    });
    const delayedOlderStore: OperationalStore = {
      execute: (statement) => olderStore.execute(statement),
      transaction: async (fn) => {
        signalOlderTransaction();
        await olderMayContinue;
        return olderStore.transaction(fn);
      },
      close: () => olderStore.close(),
    };
    const config = makePhase2Config();
    const appInput = {
      config,
      logger: { write: () => {} },
      nowMs: () => phase2NowMs,
      mastraInstance: testMastra,
    };
    const olderApp = await createApp({ ...appInput, store: delayedOlderStore });
    const newerApp = await createApp({ ...appInput, store: newerStore });
    try {
      const olderRequest = postAlert(
        olderApp,
        makeDemoWebhook({
          sourceEventId: "older-racing",
          occurredAt: "2026-08-27T11:58:00.000Z",
        }),
      );
      await olderTransactionStarted;
      const newerResponse = await postAlert(
        newerApp,
        makeDemoWebhook({
          sourceEventId: "newer-racing",
          occurredAt: "2026-08-27T11:59:00.000Z",
        }),
      );
      expect(newerResponse.status).toBe(202);
      releaseOlder();
      const olderResponse = await olderRequest;
      expect(olderResponse.status).toBe(202);
      expect(await olderResponse.json()).toMatchObject({
        accepted: false,
        reasonCode: "EVENT_OUT_OF_ORDER",
      });
      expect(await counts(newerStore)).toMatchObject({
        incidents: 1,
        alerts: 1,
        dead_letters: 1,
      });
    } finally {
      releaseOlder();
      delayedOlderStore.close();
      newerStore.close();
    }
  });

  it("keeps an older already-persisted event idempotent after a newer event", async () => {
    const { app, store } = await setup();
    try {
      const older = makeDemoWebhook({
        sourceEventId: "older-first",
        occurredAt: "2026-08-27T11:58:00.000Z",
      });
      expect((await postAlert(app, older)).status).toBe(202);
      expect(
        (
          await postAlert(
            app,
            makeDemoWebhook({
              sourceEventId: "newer-second",
              occurredAt: "2026-08-27T11:59:00.000Z",
            }),
          )
        ).status,
      ).toBe(202);
      const retry = await postAlert(app, older);
      expect(retry.status).toBe(202);
      expect(await retry.json()).toMatchObject({ duplicate: true });
      expect(await counts(store)).toMatchObject({
        incidents: 2,
        alerts: 2,
        dead_letters: 0,
      });
    } finally {
      store.close();
    }
  });

  it("fails closed when operational storage is unavailable", async () => {
    const { app, store } = await setup();
    store.close();
    const response = await postAlert(app, makeDemoWebhook());
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      code: "STORAGE_UNAVAILABLE",
      retryable: true,
    });
  });

  it("preserves health and an official Mastra route on the same Hono app", async () => {
    const { app, store } = await setup();
    try {
      const health = await app.request("/health");
      expect(health.status).toBe(200);
      expect(health.headers.get("referrer-policy")).toBe("no-referrer");
      const workflows = await app.request("/api/workflows");
      expect(workflows.status).not.toBe(404);
    } finally {
      store.close();
    }
  });

  it("returns a stable 413 envelope for an oversized official Mastra request", async () => {
    const { app, store } = await setup(65_536, 1_024);
    try {
      const response = await app.request("/api/workflows/missing/start-async", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: "x".repeat(2_000) }),
      });
      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({
        code: "PAYLOAD_TOO_LARGE",
        message: "The request body is too large.",
        requestId: "request-1",
        retryable: false,
      });
    } finally {
      store.close();
    }
  });
});
