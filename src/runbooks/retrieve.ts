import { z } from "zod";

import type { OperationalStore } from "../db/operational-store.js";
import {
  claimRetrievalSelection,
  findSuccessfulRetrieval,
  listAuthoritativeChunks,
  persistFailedRetrieval,
  persistSuccessfulRetrieval,
  type PersistedRetrievalChunk,
  type PersistedSelection,
} from "../db/runbook-retrieval-operations.js";
import { resolveEligibleGeneration } from "../db/runbook-operations.js";
import { DomainError } from "../domain/errors.js";
import type { IdGenerator } from "../domain/id-generator.js";
import type { Clock } from "../domain/clock.js";
import { opaqueId } from "../schemas/common.js";
import { IncidentKindSchema } from "../schemas/incident.js";
import { validatePersistedAllowedActions } from "./allowlist.js";
import type { RunbookEmbedder } from "./embeddings.js";
import { RunbookError, type RunbookErrorCode } from "./errors.js";
import { canonicalJson, sha256 } from "./hashes.js";
import { RunbookChunkMetadataSchema } from "./schemas.js";
import type { RunbookVectorStore } from "./vector-store.js";

export const RetrieveRunbookInputSchema = z
  .object({
    incidentId: opaqueId,
    tenantId: opaqueId,
    workflowRunId: opaqueId,
    correlationId: opaqueId,
    incidentKind: IncidentKindSchema,
    queryText: z.string().max(2_048),
  })
  .strict();

export type RetrieveRunbookInput = z.infer<typeof RetrieveRunbookInputSchema>;
export type RetrieveRunbookResult = Readonly<{
  retrievalId: string;
  runbookId: string;
  version: string;
  generationId: string;
  citation: string;
  chunkIds: readonly string[];
  duplicate: boolean;
}>;

const DEFAULT_TOP_K = 3;
const DEFAULT_THRESHOLD = 0.15;

export async function retrieveRunbook(
  store: OperationalStore,
  vectorStore: RunbookVectorStore,
  embedder: RunbookEmbedder,
  untrustedInput: RetrieveRunbookInput,
  options: Readonly<{
    topK?: number;
    threshold?: number;
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
): Promise<RetrieveRunbookResult> {
  const parsed = RetrieveRunbookInputSchema.safeParse(untrustedInput);
  if (!parsed.success) throw new RunbookError("RUNBOOK_INELIGIBLE");
  const input = parsed.data;
  const topK = options.topK ?? DEFAULT_TOP_K;
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  if (
    !Number.isFinite(threshold) ||
    threshold < -1 ||
    threshold > 1 ||
    !Number.isInteger(topK) ||
    topK < 1 ||
    topK > 20
  ) {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
  const queryText = input.queryText.trim();
  const queryHash = sha256(queryText);
  if (!queryText) {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_QUERY_EMPTY",
      threshold,
      topK,
      options,
    );
    throw new RunbookError("RUNBOOK_QUERY_EMPTY");
  }
  let existing;
  try {
    existing = await findSuccessfulRetrieval(store, {
      ...input,
      queryHash,
      threshold,
      topK,
    });
  } catch {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  if (existing) return { ...existing, duplicate: true };

  let selection: PersistedSelection | undefined;
  try {
    selection = await claimRetrievalSelection(
      store,
      { ...input, queryHash, threshold, topK },
      undefined,
      options,
    );
  } catch {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  if (!selection) {
    let eligible;
    try {
      eligible = await resolveEligibleGeneration(store, input.incidentKind);
    } catch (error) {
      const code =
        error instanceof RunbookError
          ? error.code
          : error instanceof DomainError && error.code === "CONFLICT"
            ? "RUNBOOK_INELIGIBLE"
            : "RUNBOOK_BACKEND_UNAVAILABLE";
      await auditFailure(
        store,
        input,
        queryHash,
        code,
        threshold,
        topK,
        options,
      );
      throw new RunbookError(code, code === "RUNBOOK_BACKEND_UNAVAILABLE");
    }
    if (!eligible) {
      await auditFailure(
        store,
        input,
        queryHash,
        "RUNBOOK_MISSING",
        threshold,
        topK,
        options,
      );
      throw new RunbookError("RUNBOOK_MISSING");
    }
    try {
      selection = await claimRetrievalSelection(
        store,
        { ...input, queryHash, threshold, topK },
        eligible,
        options,
      );
    } catch {
      throw new RunbookError("RUNBOOK_INELIGIBLE");
    }
  }
  if (!selection) throw new RunbookError("RUNBOOK_INELIGIBLE");
  const generation = selection.generation;

  try {
    validatePersistedAllowedActions(
      input.incidentKind,
      generation.allowedActionsJson,
    );
  } catch (error) {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_ACTION_NOT_ALLOWLISTED",
      threshold,
      topK,
      options,
      selection,
    );
    throw error;
  }

  let authoritative;
  try {
    authoritative = await listAuthoritativeChunks(
      store,
      generation.generationId,
    );
  } catch {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_INTEGRITY_FAILED",
      threshold,
      topK,
      options,
      selection,
    );
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  const aggregate = sha256(
    [...authoritative.values()]
      .sort(
        (left, right) =>
          left.metadata.sectionOrdinal - right.metadata.sectionOrdinal ||
          left.metadata.chunkOrdinal - right.metadata.chunkOrdinal,
      )
      .map((chunk) => `${chunk.metadata.chunkId}:${chunk.metadataHash}`)
      .join("\n"),
  );
  if (
    authoritative.size !== generation.chunkCount ||
    aggregate !== generation.aggregateHash
  ) {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_INTEGRITY_FAILED",
      threshold,
      topK,
      options,
      selection,
    );
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }

  let matches;
  try {
    const queryVector = await embedder.embedQuery(queryText);
    matches = await vectorStore.query(generation.indexName, queryVector, topK);
  } catch {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_BACKEND_UNAVAILABLE",
      threshold,
      topK,
      options,
      selection,
    );
    throw new RunbookError("RUNBOOK_BACKEND_UNAVAILABLE", true);
  }
  const selected: PersistedRetrievalChunk[] = [];
  const matchedIds = new Set<string>();
  for (const match of matches) {
    if (!Number.isFinite(match.score) || matchedIds.has(match.id)) {
      await auditFailure(
        store,
        input,
        queryHash,
        "RUNBOOK_INTEGRITY_FAILED",
        threshold,
        topK,
        options,
        selection,
      );
      throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
    }
    matchedIds.add(match.id);
    const chunk = authoritative.get(match.id);
    const metadata = RunbookChunkMetadataSchema.safeParse(match.metadata);
    if (
      !chunk ||
      !metadata.success ||
      metadata.data.generationId !== generation.generationId ||
      metadata.data.indexName !== generation.indexName ||
      metadata.data.incidentKind !== input.incidentKind ||
      metadata.data.runbookId !== generation.runbookId ||
      metadata.data.runbookVersion !== generation.version ||
      metadata.data.sourceHash !== generation.sourceHash ||
      metadata.data.status !== "active" ||
      metadata.data.text !== chunk.text ||
      metadata.data.contentHash !== chunk.contentHash ||
      metadata.data.metadataHash !== chunk.metadataHash ||
      recomputeMetadataHash(metadata.data) !== metadata.data.metadataHash
    ) {
      await auditFailure(
        store,
        input,
        queryHash,
        "RUNBOOK_INTEGRITY_FAILED",
        threshold,
        topK,
        options,
        selection,
      );
      throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
    }
    if (match.score >= threshold)
      selected.push({ ...chunk, score: match.score, rank: 0 });
  }
  selected.sort(
    (left, right) =>
      right.score - left.score ||
      left.metadata.sectionOrdinal - right.metadata.sectionOrdinal ||
      left.metadata.chunkOrdinal - right.metadata.chunkOrdinal ||
      left.metadata.chunkId.localeCompare(right.metadata.chunkId),
  );
  const ranked = selected
    .slice(0, topK)
    .map((chunk, index) => ({ ...chunk, rank: index + 1 }));
  if (ranked.length === 0) {
    await auditFailure(
      store,
      input,
      queryHash,
      "RUNBOOK_SCORE_INSUFFICIENT",
      threshold,
      topK,
      options,
      selection,
    );
    throw new RunbookError("RUNBOOK_SCORE_INSUFFICIENT");
  }
  const retrievalId = await persistSuccessfulRetrieval(
    store,
    { ...input, queryHash, threshold, topK, selection, chunks: ranked },
    options,
  );
  return {
    retrievalId,
    runbookId: generation.runbookId,
    version: generation.version,
    generationId: generation.generationId,
    citation: selection.citation,
    chunkIds: ranked.map((chunk) => chunk.metadata.chunkId),
    duplicate: false,
  };
}

function recomputeMetadataHash(
  metadata: z.infer<typeof RunbookChunkMetadataSchema>,
): string {
  const unsigned: Partial<z.infer<typeof RunbookChunkMetadataSchema>> = {
    ...metadata,
  };
  delete unsigned.metadataHash;
  return sha256(canonicalJson(unsigned));
}

async function auditFailure(
  store: OperationalStore,
  input: RetrieveRunbookInput,
  queryHash: string,
  errorCode: RunbookErrorCode,
  threshold: number,
  topK: number,
  options: Readonly<{ clock?: Clock; ids?: IdGenerator }>,
  selection?: PersistedSelection,
): Promise<void> {
  await persistFailedRetrieval(
    store,
    { ...input, queryHash, errorCode, threshold, topK, selection },
    options,
  );
}
