import { createStep } from "@mastra/core/workflows";
import { z } from "zod";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import {
  FastEmbedRunbookEmbedder,
  type RunbookEmbedder,
} from "../../runbooks/embeddings.js";
import {
  retrieveRunbook,
  type RetrieveRunbookResult,
} from "../../runbooks/retrieve.js";
import {
  LibSqlRunbookVectorStore,
  type RunbookVectorStore,
} from "../../runbooks/vector-store.js";
import { IncidentKindSchema } from "../../schemas/incident.js";
import { opaqueId } from "../../schemas/common.js";

export const InvestigationStartedSchema = z
  .object({
    eventId: opaqueId,
    incidentId: opaqueId,
    tenantId: opaqueId,
    alertId: opaqueId,
    correlationId: opaqueId,
    runId: opaqueId,
    duplicate: z.boolean(),
  })
  .strict();

export const RunbookRetrievedSchema = z
  .object({
    runId: opaqueId,
    duplicate: z.boolean(),
    retrievalId: opaqueId,
    runbookId: z.string().regex(/^RB-IDENTITY-00[1-3]$/u),
    version: z.string().regex(/^\d+\.\d+\.\d+$/u),
    generationId: opaqueId,
    citation: z
      .string()
      .regex(/^\[runbook:RB-IDENTITY-00[1-3]@\d+\.\d+\.\d+\]$/u),
    chunkIds: z.array(z.string().regex(/^rch_[0-9a-f]{64}$/u)).max(20),
  })
  .strict();

export type RetrieveStepDependencies = Readonly<{
  openStore?: () => OperationalStore;
  openVectorStore?: () => RunbookVectorStore;
  embedder?: RunbookEmbedder;
  retrieve?: (
    store: OperationalStore,
    vectorStore: RunbookVectorStore,
    embedder: RunbookEmbedder,
    input: Parameters<typeof retrieveRunbook>[3],
  ) => Promise<RetrieveRunbookResult>;
}>;

export function createRetrieveRunbookStep(
  dependencies: RetrieveStepDependencies = {},
) {
  return createStep({
    id: "retrieve-runbook",
    description:
      "Resolves one eligible runbook generation before semantic retrieval.",
    inputSchema: InvestigationStartedSchema,
    outputSchema: RunbookRetrievedSchema,
    execute: async ({ inputData }) => {
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      let vectorStore: RunbookVectorStore | undefined;
      try {
        vectorStore = (
          dependencies.openVectorStore ?? (() => new LibSqlRunbookVectorStore())
        )();
        const result = await store.execute({
          sql: "SELECT kind FROM incidents WHERE tenant_id = ? AND id = ?",
          args: [inputData.tenantId, inputData.incidentId],
        });
        const kind = IncidentKindSchema.safeParse(result.rows[0]?.kind);
        if (!kind.success) throw new Error("Incident kind is unavailable");
        const retrieve = dependencies.retrieve ?? retrieveRunbook;
        const retrieval = await retrieve(
          store,
          vectorStore,
          dependencies.embedder ?? new FastEmbedRunbookEmbedder(),
          {
            incidentId: inputData.incidentId,
            tenantId: inputData.tenantId,
            workflowRunId: inputData.runId,
            correlationId: inputData.correlationId,
            incidentKind: kind.data,
            queryText: `identity security incident ${kind.data.replaceAll("_", " ")}`,
          },
        );
        return {
          runId: inputData.runId,
          duplicate: inputData.duplicate || retrieval.duplicate,
          retrievalId: retrieval.retrievalId,
          runbookId: retrieval.runbookId,
          version: retrieval.version,
          generationId: retrieval.generationId,
          citation: retrieval.citation,
          chunkIds: [...retrieval.chunkIds],
        };
      } finally {
        store.close();
        await vectorStore?.close();
      }
    },
  });
}
