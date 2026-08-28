import { afterEach, describe, expect, it, vi } from "vitest";

import { createIncidentFromAlert } from "../../src/db/incident-operations.js";
import { migrateOperationalStore } from "../../src/db/migrate.js";
import { fixedClock } from "../../src/domain/clock.js";
import { sequenceIdGenerator } from "../../src/domain/id-generator.js";
import { createIncidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";
import { DeterministicRunbookEmbedder } from "../../src/runbooks/embeddings.js";
import type { RunbookVectorStore } from "../../src/runbooks/vector-store.js";
import { makeAlert } from "../fixtures/domain.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "../helpers/temp-libsql.js";

const databases: TempDatabase[] = [];

afterEach(async () => {
  await Promise.all(databases.splice(0).map((database) => database.cleanup()));
});

describe("Phase 3 workflow integration", () => {
  it("runs retrieve-runbook after materializing investigation without adding later-phase behavior", async () => {
    const database = await createTempDatabase();
    databases.push(database);
    const setupStore = database.createStore();
    await migrateOperationalStore(setupStore);
    await createIncidentFromAlert(setupStore, makeAlert(), {
      clock: fixedClock("2026-08-27T12:00:00.000Z"),
      ids: sequenceIdGenerator(["incident-1", "timeline-1", "outbox-1"]),
    });
    setupStore.close();

    const retrieve = vi.fn(async () => ({
      retrievalId: "retrieval-1",
      runbookId: "RB-IDENTITY-001",
      version: "1.0.0",
      generationId: "generation-1",
      citation: "[runbook:RB-IDENTITY-001@1.0.0]",
      chunkIds: [`rch_${"a".repeat(64)}`],
      duplicate: false,
    }));
    const workflow = createIncidentIngestionWorkflow(
      () => database.createStore(),
      {
        openVectorStore: () => new NoopVectorStore(),
        embedder: new DeterministicRunbookEmbedder(),
        retrieve,
      },
      {
        supervisor: async () => ({
          scopeValidated: true,
          specialists: ["identity", "endpoint", "cloud"],
        }),
        identityInvestigator: deterministicInvestigator,
        endpointInvestigator: deterministicInvestigator,
        cloudInvestigator: deterministicInvestigator,
        correlationAnalyst: async ({ candidate }) => candidate,
      },
    );
    const run = await workflow.createRun({ runId: "outbox-1" });
    const result = await run.start({
      inputData: {
        eventId: "outbox-1",
        incidentId: "incident-1",
        tenantId: "tenant-1",
        alertId: "alert-1",
        correlationId: "correlation-1",
      },
    });
    expect(result.status).toBe("success");
    if (result.status === "success") {
      expect(result.result).toMatchObject({
        retrievalId: "retrieval-1",
        runbookId: "RB-IDENTITY-001",
        citation: "[runbook:RB-IDENTITY-001@1.0.0]",
      });
    }
    expect(retrieve).toHaveBeenCalledOnce();
    const calls = retrieve.mock.calls as unknown[][];
    expect(calls[0]?.[3]).toMatchObject({
      incidentKind: "unauthorized_privilege_change",
      workflowRunId: "outbox-1",
    });
    const verification = database.createStore();
    try {
      const row = await verification.execute({
        sql: "SELECT status FROM incidents WHERE id = 'incident-1'",
      });
      expect(row.rows[0]?.status).toBe("investigating");
    } finally {
      verification.close();
    }
  });
});

const deterministicInvestigator = async (input: {
  facts: readonly { factToken: string }[];
}) => ({
  citedFactTokens: input.facts.map((fact) => fact.factToken),
  gaps: [],
  contradictionFlags: [],
});

class NoopVectorStore implements RunbookVectorStore {
  async ensureIndex(): Promise<void> {}
  async upsert(): Promise<void> {}
  async query() {
    return [];
  }
  async describe() {
    return { dimension: 384, count: 0 };
  }
  async deleteIndex(): Promise<void> {}
  async close(): Promise<void> {}
}
