import type { OperationalStore } from "../db/operational-store.js";
import { DomainError } from "../domain/errors.js";
import {
  activateRunbookGeneration,
  claimRunbookGenerationCleanup,
  completeRunbookGenerationCleanup,
  getActivationRevision,
  markRunbookChunksIndexed,
  markRunbookGenerationFailed,
  revalidateRunbookGenerationCleanup,
  resolveEligibleGeneration,
  resolveRollbackGeneration,
  rollbackRunbookGenerationCas,
  stageRunbookGeneration,
  type EligibleGeneration,
} from "../db/runbook-operations.js";
import { listAuthoritativeChunks } from "../db/runbook-retrieval-operations.js";
import { aggregateChunks, chunkRunbook } from "./chunker.js";
import { RunbookError } from "./errors.js";
import { canonicalJson, sha256 } from "./hashes.js";
import type { LoadedRunbook } from "./loader.js";
import {
  EMBEDDING_DIMENSION,
  RunbookChunkMetadataSchema,
  type RunbookChunkMetadata,
} from "./schemas.js";
import type { RunbookEmbedder } from "./embeddings.js";
import type { RunbookVectorStore } from "./vector-store.js";

export async function indexRunbook(
  store: OperationalStore,
  vectorStore: RunbookVectorStore,
  embedder: RunbookEmbedder,
  runbook: LoadedRunbook,
  input: Readonly<{ generationId: string; now: string }>,
): Promise<
  Readonly<{
    generationId: string;
    indexName: string;
    revision: number;
    chunkCount: number;
  }>
> {
  const kind = runbook.metadata.incidentKinds[0];
  if (!kind) throw new RunbookError("RUNBOOK_VALIDATION_FAILED");
  if (runbook.metadata.status !== "active")
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  const indexName = physicalIndexName(
    kind,
    runbook.metadata.version,
    input.generationId,
  );
  const chunks = await chunkRunbook(runbook, {
    generationId: input.generationId,
    indexName,
  });
  const aggregateHash = aggregateChunks(chunks);
  const expectedRevision = await getActivationRevision(store, kind);
  const stage = await stageRunbookGeneration(store, {
    runbook,
    generationId: input.generationId,
    indexName,
    aggregateHash,
    chunks,
    createdAt: input.now,
  });
  if (stage === "existing") {
    const active = await resolveEligibleGeneration(store, kind);
    if (active?.generationId === input.generationId) {
      return {
        generationId: input.generationId,
        indexName,
        revision: active.revision,
        chunkCount: active.chunkCount,
      };
    }
  }
  try {
    await vectorStore.ensureIndex(indexName, EMBEDDING_DIMENSION);
    const vectors = await embedder.embedDocuments(
      chunks.map((chunk) => chunk.text),
    );
    if (vectors.some((vector) => vector.length !== EMBEDDING_DIMENSION)) {
      throw new Error("Embedding dimension mismatch");
    }
    await vectorStore.upsert(
      indexName,
      chunks.map((chunk) => chunk.id),
      vectors,
      chunks.map((chunk) => chunk.metadata),
    );
    const probe = vectors[0];
    if (!probe) throw new Error("Vector readback probe is unavailable");
    await verifyVectorReadback(vectorStore, indexName, probe, chunks);
    await markRunbookChunksIndexed(store, input.generationId, input.now);
    const revision = await activateRunbookGeneration(store, {
      generationId: input.generationId,
      expectedRevision,
      activatedAt: input.now,
    });
    return {
      generationId: input.generationId,
      indexName,
      revision,
      chunkCount: chunks.length,
    };
  } catch (error) {
    const errorCode =
      error instanceof RunbookError && error.code === "RUNBOOK_INTEGRITY_FAILED"
        ? "RUNBOOK_INTEGRITY_FAILED"
        : error instanceof DomainError && error.code === "CONFLICT"
          ? "RUNBOOK_INELIGIBLE"
          : "RUNBOOK_BACKEND_UNAVAILABLE";
    await markRunbookGenerationFailed(store, input.generationId, errorCode);
    if (stage === "created") {
      try {
        await vectorStore.deleteIndex(indexName);
      } catch {
        // The failed generation remains ineligible and records the safe failure.
      }
    }
    if (error instanceof RunbookError) throw error;
    throw new RunbookError(
      errorCode,
      errorCode === "RUNBOOK_BACKEND_UNAVAILABLE",
    );
  }
}

export function physicalIndexName(
  kind: string,
  version: string,
  generationId: string,
): string {
  const safeKind = kind.replaceAll(/[^a-z0-9]+/gu, "_");
  const safeVersion = version.replaceAll(".", "_");
  return `rb_${safeKind}_${safeVersion}_${sha256(generationId).slice(0, 16)}`;
}

export async function cleanupRunbookGeneration(
  store: OperationalStore,
  vectorStore: RunbookVectorStore,
  input: Readonly<{
    generationId: string;
    indexName: string;
    expectedChunkCount: number;
    dryRun: boolean;
    now?: string;
  }>,
): Promise<Readonly<{ eligible: true; deleted: boolean }>> {
  const cleanupInput = {
    generationId: input.generationId,
    indexName: input.indexName,
    expectedChunkCount: input.expectedChunkCount,
  };
  const now = input.now ?? new Date().toISOString();
  let claim;
  try {
    claim = await claimRunbookGenerationCleanup(
      store,
      cleanupInput,
      now,
      input.dryRun,
    );
  } catch {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
  if (input.dryRun) return { eligible: true, deleted: false };
  if (claim === "deleted") return { eligible: true, deleted: true };
  try {
    await revalidateRunbookGenerationCleanup(
      store,
      cleanupInput,
      input.now ?? new Date().toISOString(),
    );
  } catch {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
  try {
    await vectorStore.deleteIndex(input.indexName);
    await completeRunbookGenerationCleanup(
      store,
      cleanupInput,
      input.now ?? new Date().toISOString(),
    );
  } catch {
    throw new RunbookError("RUNBOOK_BACKEND_UNAVAILABLE", true);
  }
  return { eligible: true, deleted: true };
}

export async function rollbackRunbookGeneration(
  store: OperationalStore,
  vectorStore: RunbookVectorStore,
  embedder: RunbookEmbedder,
  input: Readonly<{
    generationId: string;
    expectedRevision: number;
    now: string;
  }>,
): Promise<Readonly<{ generationId: string; revision: number }>> {
  let generation;
  try {
    generation = await resolveRollbackGeneration(store, input.generationId);
  } catch {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
  if (generation.revision !== input.expectedRevision) {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
  await verifyGenerationIndex(store, vectorStore, embedder, generation);
  try {
    const revision = await rollbackRunbookGenerationCas(store, {
      generationId: input.generationId,
      expectedRevision: input.expectedRevision,
      rolledBackAt: input.now,
    });
    return { generationId: input.generationId, revision };
  } catch {
    throw new RunbookError("RUNBOOK_INELIGIBLE");
  }
}

async function verifyGenerationIndex(
  store: OperationalStore,
  vectorStore: RunbookVectorStore,
  embedder: RunbookEmbedder,
  generation: EligibleGeneration,
): Promise<void> {
  let authoritative;
  try {
    authoritative = await listAuthoritativeChunks(
      store,
      generation.generationId,
    );
  } catch {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  const ordered = [...authoritative.values()].sort(
    (left, right) =>
      left.metadata.sectionOrdinal - right.metadata.sectionOrdinal ||
      left.metadata.chunkOrdinal - right.metadata.chunkOrdinal,
  );
  const aggregate = sha256(
    ordered
      .map((chunk) => `${chunk.metadata.chunkId}:${chunk.metadataHash}`)
      .join("\n"),
  );
  if (
    ordered.length !== generation.chunkCount ||
    aggregate !== generation.aggregateHash
  ) {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  try {
    const first = ordered[0];
    if (!first) {
      throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
    }
    const probe = await embedder.embedQuery(first.text);
    await verifyVectorReadback(
      vectorStore,
      generation.indexName,
      probe,
      ordered,
    );
  } catch (error) {
    if (error instanceof RunbookError) throw error;
    throw new RunbookError("RUNBOOK_BACKEND_UNAVAILABLE", true);
  }
}

type VerifiableChunk = Readonly<{
  metadata: RunbookChunkMetadata;
  text: string;
}>;

async function verifyVectorReadback(
  vectorStore: RunbookVectorStore,
  indexName: string,
  probe: readonly number[],
  chunks: readonly VerifiableChunk[],
): Promise<void> {
  const stats = await vectorStore.describe(indexName);
  if (
    stats.dimension !== EMBEDDING_DIMENSION ||
    stats.count !== chunks.length
  ) {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  const readback = await vectorStore.query(indexName, probe, chunks.length);
  const expected = new Map(
    chunks.map((chunk) => [chunk.metadata.chunkId, chunk] as const),
  );
  if (readback.length !== chunks.length) {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
  for (const match of readback) {
    const chunk = expected.get(match.id);
    const metadata = RunbookChunkMetadataSchema.safeParse(match.metadata);
    if (!chunk || !metadata.success) {
      throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
    }
    const unsigned: Partial<RunbookChunkMetadata> = { ...metadata.data };
    delete unsigned.metadataHash;
    if (
      metadata.data.chunkId !== match.id ||
      canonicalJson(metadata.data) !== canonicalJson(chunk.metadata) ||
      metadata.data.text !== chunk.text ||
      metadata.data.contentHash !== chunk.metadata.contentHash ||
      metadata.data.metadataHash !== chunk.metadata.metadataHash ||
      sha256(metadata.data.text) !== metadata.data.contentHash ||
      sha256(canonicalJson(unsigned)) !== metadata.data.metadataHash
    ) {
      throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
    }
    expected.delete(match.id);
  }
  if (expected.size !== 0) {
    throw new RunbookError("RUNBOOK_INTEGRITY_FAILED");
  }
}
