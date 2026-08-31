import { Mastra } from "@mastra/core/mastra";
import { LibSQLStore } from "@mastra/libsql";
import { createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { startServerRuntime } from "../../src/background/runtime.js";
import { createLibSqlOperationalStore } from "../../src/db/libsql-operational-store.js";
import { baselineWorkflow } from "../../src/mastra/workflows/baseline-workflow.js";
import { createIncidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import { makePhase2Config } from "../fixtures/phase2.js";
import { readPhase8Config } from "../../src/env.js";
import { retentionIntervalMs } from "../../src/config/retention.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("server lifecycle", () => {
  it("injects the validated F8 config into the nominal Hono route without falling back to mock", async () => {
    vi.stubEnv("WORKOS_API_KEY", "runtime-control-plane-key");
    vi.stubEnv("WORKOS_CLIENT_ID", "runtime-control-plane-client");
    vi.stubEnv(
      "WORKOS_REDIRECT_URI",
      "https://dashboard.example.test/callback",
    );
    vi.stubEnv("WORKOS_COOKIE_PASSWORD", "x".repeat(32));
    const database = await createTempDatabase();
    databases.push(database);
    const workflow = createIncidentIngestionWorkflow(() =>
      createLibSqlOperationalStore({ url: database.url }),
    );
    const mastra = new Mastra({
      storage: new LibSQLStore({ id: "lifecycle-workos", url: database.url }),
      workflows: { baselineWorkflow, incidentIngestionWorkflow: workflow },
    });
    const secret = "current-workos-webhook-secret";
    const phase8Config = readPhase8Config({
      DEMO_MODE: "staging",
      WEBHOOKS_ENABLED: "true",
      WORKOS_PROVIDER_ENABLED: "true",
      WORKOS_API_KEY: "fake-workos-api-key",
      WORKOS_WEBHOOK_SECRET: secret,
      WORKOS_STAGING_ORGANIZATION_ID: "tenant-1",
      WORKOS_STAGING_ALLOWED_USER_IDS: "subject-1",
      WORKOS_STAGING_ALLOWED_ROLE_SLUGS: "member,admin,viewer",
    });
    const now = Date.now();
    const bytes = new TextEncoder().encode(
      `{ "id":"runtime-workos-1", "event":"organization_membership.updated", "created_at":"${new Date().toISOString()}", "data": { "object":"organization_membership", "id":"membership-runtime-1", "organization_id":"tenant-1", "organization_name":"Synthetic", "user_id":"subject-1", "status":"active", "directory_managed":false, "created_at":"${new Date().toISOString()}", "updated_at":"${new Date().toISOString()}", "custom_attributes":{}, "role":{"slug":"admin"} } }`,
    );
    const signature = createHmac("sha256", secret)
      .update(`${now}.`, "utf8")
      .update(bytes)
      .digest("hex");
    let nominalStatus = 0;
    let mockStatus = 0;
    const genericControlPlaneStatuses: number[] = [];
    const runtime = await startServerRuntime({
      config: makePhase2Config({
        outbox: { ...makePhase2Config().outbox, pollIntervalMs: 60_000 },
      }),
      phase8Config,
      store: database.createStore(),
      mastraInstance: mastra,
      logger: { write: () => {} },
      port: 0,
      bindServer: async (fetch) => ({
        port: 43_211,
        close: async () => {
          nominalStatus = (
            await fetch(
              new Request("http://local/webhooks/workos", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "WorkOS-Signature": `t=${now},v1=${signature}`,
                },
                body: bytes,
              }),
            )
          ).status;
          mockStatus = (
            await fetch(
              new Request("http://local/webhooks/workos/mock", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "WorkOS-Signature": `t=${now},v1=${signature}`,
                },
                body: bytes,
              }),
            )
          ).status;
          for (const path of [
            "/api/workflows",
            "/api/workflows/incidentIngestionWorkflow/runs",
            "/api/agents/socSupervisor/tools",
          ])
            genericControlPlaneStatuses.push(
              (await fetch(new Request(`http://local${path}`))).status,
            );
        },
      }),
    });
    await runtime.stop();
    expect(nominalStatus).toBe(202);
    expect(mockStatus).toBe(401);
    expect(genericControlPlaneStatuses).toEqual([401, 401, 401]);
  });

  it("starts in the required order and stops idempotently without an owned timer", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const workflow = createIncidentIngestionWorkflow(() =>
      createLibSqlOperationalStore({ url: database.url }),
    );
    const storage = new LibSQLStore({
      id: "lifecycle-test",
      url: database.url,
    });
    const mastra = new Mastra({
      storage,
      workflows: {
        baselineWorkflow,
        incidentIngestionWorkflow: workflow,
      },
    });
    const startupOrder: string[] = [];
    const runtime = await startServerRuntime({
      config: makePhase2Config({
        outbox: {
          ...makePhase2Config().outbox,
          pollIntervalMs: 60_000,
        },
      }),
      store: database.createStore(),
      mastraInstance: mastra,
      initializeStorage: async () => {
        startupOrder.push("storage.init");
      },
      logger: { write: () => {} },
      port: 0,
      bindServer: async (fetch) => ({
        port: 43_210,
        close: async () => {
          const response = await fetch(new Request("http://local/health"));
          expect(response.status).toBe(200);
        },
      }),
    });
    expect(startupOrder).toEqual(["storage.init"]);
    expect(runtime.port).toBe(43_210);
    await runtime.stop();
    await runtime.stop();
  });

  it("runs the explicitly scoped retention scheduler in the runtime lifecycle", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const workflow = createIncidentIngestionWorkflow(() =>
      createLibSqlOperationalStore({ url: database.url }),
    );
    const mastra = new Mastra({
      storage: new LibSQLStore({
        id: "retention-lifecycle",
        url: database.url,
      }),
      workflows: {
        baselineWorkflow,
        incidentIngestionWorkflow: workflow,
      },
    });
    const runtime = await startServerRuntime({
      config: makePhase2Config({
        outbox: { ...makePhase2Config().outbox, pollIntervalMs: 60_000 },
      }),
      retentionConfig: {
        enabled: true,
        tenantId: "tenant-a",
        limit: 8,
        intervalMs: retentionIntervalMs,
      },
      store: database.createStore(),
      mastraInstance: mastra,
      logger: { write: () => {} },
      port: 0,
      bindServer: async () => ({ port: 43_209, close: async () => {} }),
    });
    await expect(
      database.createStore().execute({
        sql: "SELECT next_source FROM retention_source_cursors WHERE tenant_id='tenant-a'",
      }),
    ).resolves.toMatchObject({
      rows: [{ next_source: 1 }],
    });
    await runtime.stop();
  });
});
