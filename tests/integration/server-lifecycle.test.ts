import { Mastra } from "@mastra/core/mastra";
import { LibSQLStore } from "@mastra/libsql";
import { afterEach, describe, expect, it } from "vitest";

import { startServerRuntime } from "../../src/background/runtime.js";
import { createLibSqlOperationalStore } from "../../src/db/libsql-operational-store.js";
import { baselineWorkflow } from "../../src/mastra/workflows/baseline-workflow.js";
import { createIncidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import { makePhase2Config } from "../fixtures/phase2.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("server lifecycle", () => {
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
    const runtime = await startServerRuntime({
      config: makePhase2Config({
        outbox: {
          ...makePhase2Config().outbox,
          pollIntervalMs: 60_000,
        },
      }),
      store: database.createStore(),
      mastraInstance: mastra,
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
    expect(runtime.port).toBe(43_210);
    await runtime.stop();
    await runtime.stop();
  });
});
