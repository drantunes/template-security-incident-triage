import type { Clock } from "../domain/clock.js";
import { systemClock } from "../domain/clock.js";
import { DomainError } from "../domain/errors.js";
import type { IdGenerator } from "../domain/id-generator.js";
import { uuidGenerator } from "../domain/id-generator.js";
import type { RunbookErrorCode } from "../runbooks/errors.js";
import { canonicalJson, sha256 } from "../runbooks/hashes.js";
import {
  RunbookChunkMetadataSchema,
  type RunbookChunkMetadata,
} from "../runbooks/schemas.js";
import type { EligibleGeneration } from "./runbook-operations.js";
import type {
  OperationalStore,
  StoreTransaction,
} from "./operational-store.js";

export type AuthoritativeChunk = Readonly<{
  metadata: RunbookChunkMetadata;
  text: string;
  contentHash: string;
  metadataHash: string;
}>;

export type PersistedRetrievalChunk = AuthoritativeChunk &
  Readonly<{ score: number; rank: number }>;

export type RetrievalScope = Readonly<{
  tenantId: string;
  incidentId: string;
  workflowRunId: string;
  correlationId: string;
  incidentKind: string;
  queryHash: string;
  threshold: number;
  topK: number;
}>;

export type PersistedSelection = Readonly<{
  retrievalId: string;
  generation: EligibleGeneration;
  citation: string;
  selectedAt: string;
  selectionIntegrityHash: string;
  attempt: number;
  leaseToken?: string;
  leaseExpiresAt?: string;
}>;

const POLICY_VERSION = 1;
const RETRIEVAL_LEASE_MS = 60_000;

export async function listAuthoritativeChunks(
  store: OperationalStore,
  generationId: string,
): Promise<ReadonlyMap<string, AuthoritativeChunk>> {
  const result = await store.execute({
    sql: `SELECT chunk_id, text, content_hash, metadata_hash, metadata_json
      FROM runbook_chunks WHERE generation_id = ? AND indexed_at IS NOT NULL`,
    args: [generationId],
  });
  const chunks = new Map<string, AuthoritativeChunk>();
  for (const row of result.rows) {
    if (typeof row.metadata_json !== "string" || typeof row.text !== "string") {
      throw new DomainError("VALIDATION_FAILED");
    }
    let metadataValue: unknown;
    try {
      metadataValue = JSON.parse(row.metadata_json);
    } catch {
      throw new DomainError("VALIDATION_FAILED");
    }
    const metadata = RunbookChunkMetadataSchema.safeParse(metadataValue);
    if (
      !metadata.success ||
      metadata.data.chunkId !== row.chunk_id ||
      metadata.data.text !== row.text ||
      metadata.data.contentHash !== row.content_hash ||
      metadata.data.metadataHash !== row.metadata_hash ||
      sha256(row.text) !== row.content_hash ||
      recomputeMetadataHash(metadata.data) !== row.metadata_hash
    )
      throw new DomainError("VALIDATION_FAILED");
    chunks.set(metadata.data.chunkId, {
      metadata: metadata.data,
      text: row.text,
      contentHash: String(row.content_hash),
      metadataHash: String(row.metadata_hash),
    });
  }
  return chunks;
}

export async function findSuccessfulRetrieval(
  store: OperationalStore,
  input: RetrievalScope,
): Promise<
  | Readonly<{
      retrievalId: string;
      runbookId: string;
      version: string;
      generationId: string;
      citation: string;
      chunkIds: readonly string[];
    }>
  | undefined
> {
  const result = await store.execute({
    sql: `${selectionQuery}
      WHERE r.tenant_id = ? AND r.incident_id = ? AND r.workflow_run_id = ?
        AND r.query_hash = ? AND r.policy_version = 1 AND r.status = 'succeeded'`,
    args: [
      input.tenantId,
      input.incidentId,
      input.workflowRunId,
      input.queryHash,
    ],
  });
  const row = result.rows[0];
  if (!row) return undefined;
  const selection = validateSelectionRow(row, input);
  const chunks = await store.execute({
    sql: `SELECT rc.rank, rc.generation_id, rc.chunk_id, rc.vector_id,
      rc.content_hash, rc.metadata_hash, rc.score_text, rc.score,
      rc.section_ordinal, rc.chunk_ordinal,
      c.content_hash AS current_content_hash,
      c.metadata_hash AS current_metadata_hash
      FROM runbook_retrieval_chunks rc
      JOIN runbook_chunks c ON c.generation_id = rc.generation_id
        AND c.chunk_id = rc.chunk_id AND c.vector_id = rc.vector_id
      WHERE rc.retrieval_id = ? ORDER BY rc.rank`,
    args: [selection.retrievalId],
  });
  if (chunks.rows.length === 0) throw new DomainError("VALIDATION_FAILED");
  const integrityChunks = chunks.rows.map((chunk, index) => {
    const score = Number(chunk.score);
    if (
      Number(chunk.rank) !== index + 1 ||
      chunk.generation_id !== selection.generation.generationId ||
      !Number.isFinite(score) ||
      typeof chunk.score_text !== "string" ||
      Number(chunk.score_text) !== score ||
      chunk.content_hash !== chunk.current_content_hash ||
      chunk.metadata_hash !== chunk.current_metadata_hash
    )
      throw new DomainError("VALIDATION_FAILED");
    return {
      id: String(chunk.chunk_id),
      vectorId: String(chunk.vector_id),
      rank: Number(chunk.rank),
      score: chunk.score_text,
      contentHash: String(chunk.content_hash),
      metadataHash: String(chunk.metadata_hash),
      sectionOrdinal: Number(chunk.section_ordinal),
      chunkOrdinal: Number(chunk.chunk_ordinal),
    };
  });
  const aggregate = successfulIntegrityHash(selection, input, integrityChunks);
  if (aggregate !== row.aggregate_integrity_hash) {
    throw new DomainError("VALIDATION_FAILED");
  }
  return {
    retrievalId: selection.retrievalId,
    runbookId: selection.generation.runbookId,
    version: selection.generation.version,
    generationId: selection.generation.generationId,
    citation: selection.citation,
    chunkIds: integrityChunks.map((chunk) => chunk.id),
  };
}

export async function claimRetrievalSelection(
  store: OperationalStore,
  input: RetrievalScope,
  generation: EligibleGeneration | undefined,
  dependencies: Readonly<{ clock?: Clock; ids?: IdGenerator }> = {},
): Promise<PersistedSelection | undefined> {
  const now = (dependencies.clock ?? systemClock).now();
  return store.transaction(async (tx) => {
    const existing = await tx.execute({
      sql: `${selectionQuery}
        WHERE r.tenant_id = ? AND r.incident_id = ? AND r.workflow_run_id = ?
          AND r.query_hash = ? AND r.policy_version = 1`,
      args: [
        input.tenantId,
        input.incidentId,
        input.workflowRunId,
        input.queryHash,
      ],
    });
    if (existing.rows[0]) {
      const row = existing.rows[0];
      const selection = validateSelectionRow(row, input);
      await assertCleanupNotClaimed(tx, selection.generation.generationId);
      const nextAttempt = selection.attempt + 1;
      const leaseToken = retrievalLeaseToken(
        selection.retrievalId,
        nextAttempt,
        now,
      );
      const leaseExpiresAt = retrievalLeaseExpiry(now);
      let updated;
      if (
        row.status === "failed" &&
        row.error_code === "RUNBOOK_BACKEND_UNAVAILABLE"
      ) {
        if (
          typeof row.finished_at !== "string" ||
          row.aggregate_integrity_hash !==
            failedIntegrityHash(
              selection.retrievalId,
              selection.selectionIntegrityHash,
              "RUNBOOK_BACKEND_UNAVAILABLE",
              input.queryHash,
              row.finished_at,
              "failed",
              selection.attempt,
            )
        ) {
          throw new DomainError("VALIDATION_FAILED");
        }
        updated = await tx.execute({
          sql: `UPDATE runbook_retrievals SET status = 'in_progress', error_code = NULL,
            attempt = ?, lease_token = ?, lease_expires_at = ?,
            finished_at = NULL, aggregate_integrity_hash = NULL
            WHERE retrieval_id = ? AND status = 'failed'
              AND error_code = 'RUNBOOK_BACKEND_UNAVAILABLE' AND attempt = ?`,
          args: [
            nextAttempt,
            leaseToken,
            leaseExpiresAt,
            selection.retrievalId,
            selection.attempt,
          ],
        });
      } else if (
        row.status === "in_progress" &&
        typeof row.lease_token === "string" &&
        typeof row.lease_expires_at === "string" &&
        row.lease_expires_at <= now
      ) {
        updated = await tx.execute({
          sql: `UPDATE runbook_retrievals SET attempt = ?, lease_token = ?,
            lease_expires_at = ? WHERE retrieval_id = ? AND status = 'in_progress'
            AND attempt = ? AND lease_token = ? AND lease_expires_at <= ?`,
          args: [
            nextAttempt,
            leaseToken,
            leaseExpiresAt,
            selection.retrievalId,
            selection.attempt,
            row.lease_token,
            now,
          ],
        });
      } else {
        throw new DomainError("CONFLICT");
      }
      if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
      return {
        ...selection,
        attempt: nextAttempt,
        leaseToken,
        leaseExpiresAt,
      };
    }
    if (!generation) return undefined;
    const proposedRetrievalId = (dependencies.ids ?? uuidGenerator).next();
    await assertCurrentSelection(tx, generation);
    await assertCleanupNotClaimed(tx, generation.generationId);
    const citation = canonicalCitation(
      generation.runbookId,
      generation.version,
    );
    const attempt = 1;
    const leaseToken = retrievalLeaseToken(proposedRetrievalId, attempt, now);
    const leaseExpiresAt = retrievalLeaseExpiry(now);
    const selection = {
      retrievalId: proposedRetrievalId,
      generation,
      citation,
      selectedAt: now,
      selectionIntegrityHash: selectionIntegrityHash(
        proposedRetrievalId,
        generation,
        citation,
        input,
        now,
      ),
      attempt,
      leaseToken,
      leaseExpiresAt,
    };
    await tx.execute({
      sql: `INSERT INTO runbook_retrievals(
        retrieval_id, tenant_id, incident_id, workflow_run_id, correlation_id,
        incident_kind, runbook_id, version, generation_id, index_name,
        activation_revision, source_hash, generation_aggregate_hash, citation,
        allowed_actions_json,
        query_hash, status, error_code, attempt, lease_token, lease_expires_at,
        threshold, top_k, policy_version,
        selected_at, finished_at, selection_integrity_hash, aggregate_integrity_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'in_progress',
        NULL, ?, ?, ?, ?, ?, 1, ?, NULL, ?, NULL)`,
      args: [
        selection.retrievalId,
        input.tenantId,
        input.incidentId,
        input.workflowRunId,
        input.correlationId,
        generation.incidentKind,
        generation.runbookId,
        generation.version,
        generation.generationId,
        generation.indexName,
        generation.revision,
        generation.sourceHash,
        generation.aggregateHash,
        citation,
        generation.allowedActionsJson,
        input.queryHash,
        attempt,
        leaseToken,
        leaseExpiresAt,
        input.threshold.toString(),
        input.topK,
        now,
        selection.selectionIntegrityHash,
      ],
    });
    return selection;
  });
}

export async function persistSuccessfulRetrieval(
  store: OperationalStore,
  input: RetrievalScope &
    Readonly<{
      selection: PersistedSelection;
      chunks: readonly PersistedRetrievalChunk[];
    }>,
  dependencies: Readonly<{ clock?: Clock; ids?: IdGenerator }> = {},
): Promise<string> {
  const timelineId = (dependencies.ids ?? uuidGenerator).next();
  const now = (dependencies.clock ?? systemClock).now();
  const integrityChunks = input.chunks.map((chunk) => ({
    id: chunk.metadata.chunkId,
    vectorId: chunk.metadata.vectorId,
    rank: chunk.rank,
    score: chunk.score.toString(),
    contentHash: chunk.contentHash,
    metadataHash: chunk.metadataHash,
    sectionOrdinal: chunk.metadata.sectionOrdinal,
    chunkOrdinal: chunk.metadata.chunkOrdinal,
  }));
  const aggregate = successfulIntegrityHash(
    input.selection,
    input,
    integrityChunks,
  );
  return store.transaction(async (tx) => {
    if (!input.selection.leaseToken || !input.selection.leaseExpiresAt) {
      throw new DomainError("CONFLICT");
    }
    await assertCleanupNotClaimed(tx, input.selection.generation.generationId);
    const current = await tx.execute({
      sql: `${selectionQuery} WHERE r.retrieval_id = ?`,
      args: [input.selection.retrievalId],
    });
    if (
      !current.rows[0] ||
      current.rows[0].status !== "in_progress" ||
      current.rows[0].lease_token !== input.selection.leaseToken ||
      Number(current.rows[0].attempt) !== input.selection.attempt ||
      current.rows[0].lease_expires_at !== input.selection.leaseExpiresAt ||
      input.selection.leaseExpiresAt <= now ||
      validateSelectionRow(current.rows[0], input).selectionIntegrityHash !==
        input.selection.selectionIntegrityHash
    ) {
      throw new DomainError("CONFLICT");
    }
    for (const chunk of input.chunks) {
      await tx.execute({
        sql: `INSERT INTO runbook_retrieval_chunks(
          retrieval_id, rank, generation_id, chunk_id, vector_id, content_hash,
          metadata_hash, score_text, score, section_ordinal, chunk_ordinal
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          input.selection.retrievalId,
          chunk.rank,
          input.selection.generation.generationId,
          chunk.metadata.chunkId,
          chunk.metadata.vectorId,
          chunk.contentHash,
          chunk.metadataHash,
          chunk.score.toString(),
          chunk.score,
          chunk.metadata.sectionOrdinal,
          chunk.metadata.chunkOrdinal,
        ],
      });
    }
    const finished = await tx.execute({
      sql: `UPDATE runbook_retrievals SET status = 'succeeded', finished_at = ?,
        lease_token = NULL, lease_expires_at = NULL, aggregate_integrity_hash = ?
        WHERE retrieval_id = ? AND status = 'in_progress' AND attempt = ?
          AND lease_token = ? AND lease_expires_at > ?`,
      args: [
        now,
        aggregate,
        input.selection.retrievalId,
        input.selection.attempt,
        input.selection.leaseToken,
        now,
      ],
    });
    if (finished.rowsAffected !== 1) throw new DomainError("CONFLICT");
    await appendTimeline(tx, {
      timelineId,
      type: "runbook.retrieved",
      now,
      input,
      payload: {
        retrievalId: input.selection.retrievalId,
        runbookId: input.selection.generation.runbookId,
        version: input.selection.generation.version,
        generationId: input.selection.generation.generationId,
        chunkIds: input.chunks.map((chunk) => chunk.metadata.chunkId).join(","),
      },
    });
    return input.selection.retrievalId;
  });
}

export async function persistFailedRetrieval(
  store: OperationalStore,
  input: RetrievalScope &
    Readonly<{
      errorCode: RunbookErrorCode;
      selection?: PersistedSelection;
    }>,
  dependencies: Readonly<{ clock?: Clock; ids?: IdGenerator }> = {},
): Promise<string> {
  const ids = dependencies.ids ?? uuidGenerator;
  const retrievalId = input.selection?.retrievalId ?? ids.next();
  const timelineId = ids.next();
  const now = (dependencies.clock ?? systemClock).now();
  const status =
    input.errorCode === "RUNBOOK_SCORE_INSUFFICIENT"
      ? "manual_review"
      : "failed";
  const aggregate = failedIntegrityHash(
    retrievalId,
    input.selection?.selectionIntegrityHash ?? null,
    input.errorCode,
    input.queryHash,
    now,
    status,
    input.selection?.attempt ?? 0,
  );
  return store.transaction(async (tx) => {
    const existing = await tx.execute({
      sql: `${selectionQuery}
        WHERE r.tenant_id = ? AND r.incident_id = ? AND r.workflow_run_id = ?
          AND r.query_hash = ? AND r.policy_version = 1`,
      args: [
        input.tenantId,
        input.incidentId,
        input.workflowRunId,
        input.queryHash,
      ],
    });
    if (existing.rows[0]) {
      if (!input.selection) {
        if (existing.rows[0].error_code !== input.errorCode)
          throw new DomainError("CONFLICT");
        return String(existing.rows[0].retrieval_id);
      }
      const persisted = validateSelectionRow(existing.rows[0], input);
      await assertCleanupNotClaimed(
        tx,
        input.selection.generation.generationId,
      );
      if (
        existing.rows[0].status !== "in_progress" ||
        !input.selection.leaseToken ||
        !input.selection.leaseExpiresAt ||
        input.selection.leaseExpiresAt <= now ||
        existing.rows[0].lease_token !== input.selection.leaseToken ||
        Number(existing.rows[0].attempt) !== input.selection.attempt ||
        persisted.selectionIntegrityHash !==
          input.selection.selectionIntegrityHash
      ) {
        throw new DomainError("CONFLICT");
      }
      const updated = await tx.execute({
        sql: `UPDATE runbook_retrievals SET status = ?, error_code = ?,
          lease_token = NULL, lease_expires_at = NULL,
          finished_at = ?, aggregate_integrity_hash = ?
          WHERE retrieval_id = ? AND status = 'in_progress' AND attempt = ?
            AND lease_token = ? AND lease_expires_at > ?`,
        args: [
          status,
          input.errorCode,
          now,
          aggregate,
          retrievalId,
          input.selection.attempt,
          input.selection.leaseToken,
          now,
        ],
      });
      if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
    } else {
      if (input.selection) throw new DomainError("CONFLICT");
      await tx.execute({
        sql: `INSERT INTO runbook_retrievals(
          retrieval_id, tenant_id, incident_id, workflow_run_id, correlation_id,
          incident_kind, query_hash, status, error_code, threshold, top_k,
          policy_version, selected_at, finished_at, aggregate_integrity_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
        args: [
          retrievalId,
          input.tenantId,
          input.incidentId,
          input.workflowRunId,
          input.correlationId,
          input.incidentKind,
          input.queryHash,
          status,
          input.errorCode,
          input.threshold.toString(),
          input.topK,
          now,
          now,
          aggregate,
        ],
      });
    }
    await appendTimeline(tx, {
      timelineId,
      type: "runbook.retrieval_failed",
      now,
      input,
      payload: { retrievalId, errorCode: input.errorCode },
    });
    return retrievalId;
  });
}

const selectionQuery = `SELECT r.*, g.index_name AS current_index_name,
  g.chunk_count AS current_chunk_count, g.aggregate_hash AS current_aggregate_hash,
  g.incident_kind AS current_incident_kind, v.source_hash AS current_source_hash,
  v.allowed_actions_json AS current_allowed_actions_json
  FROM runbook_retrievals r
  LEFT JOIN runbook_generations g ON g.generation_id = r.generation_id
    AND g.runbook_id = r.runbook_id AND g.version = r.version
    AND g.incident_kind = r.incident_kind
  LEFT JOIN runbook_versions v ON v.runbook_id = r.runbook_id AND v.version = r.version`;

function validateSelectionRow(
  row: Record<string, unknown>,
  input: RetrievalScope,
): PersistedSelection {
  if (
    typeof row.retrieval_id !== "string" ||
    typeof row.runbook_id !== "string" ||
    typeof row.version !== "string" ||
    typeof row.generation_id !== "string" ||
    typeof row.index_name !== "string" ||
    typeof row.source_hash !== "string" ||
    typeof row.generation_aggregate_hash !== "string" ||
    typeof row.allowed_actions_json !== "string" ||
    typeof row.citation !== "string" ||
    typeof row.selected_at !== "string" ||
    typeof row.selection_integrity_hash !== "string" ||
    row.tenant_id !== input.tenantId ||
    row.incident_id !== input.incidentId ||
    row.workflow_run_id !== input.workflowRunId ||
    row.correlation_id !== input.correlationId ||
    row.incident_kind !== input.incidentKind ||
    row.query_hash !== input.queryHash ||
    row.threshold !== input.threshold.toString() ||
    Number(row.top_k) !== input.topK ||
    Number(row.policy_version) !== POLICY_VERSION ||
    row.index_name !== row.current_index_name ||
    row.source_hash !== row.current_source_hash ||
    row.generation_aggregate_hash !== row.current_aggregate_hash ||
    row.allowed_actions_json !== row.current_allowed_actions_json ||
    row.incident_kind !== row.current_incident_kind ||
    row.citation !== canonicalCitation(row.runbook_id, row.version)
  ) {
    throw new DomainError("VALIDATION_FAILED");
  }
  const generation: EligibleGeneration = {
    incidentKind: row.incident_kind as EligibleGeneration["incidentKind"],
    runbookId: row.runbook_id,
    version: row.version,
    generationId: row.generation_id,
    indexName: row.index_name,
    revision: Number(row.activation_revision),
    chunkCount: Number(row.current_chunk_count),
    aggregateHash: row.generation_aggregate_hash,
    allowedActionsJson: row.allowed_actions_json,
    sourceHash: row.source_hash,
  };
  const expectedHash = selectionIntegrityHash(
    row.retrieval_id,
    generation,
    row.citation,
    input,
    row.selected_at,
  );
  if (expectedHash !== row.selection_integrity_hash)
    throw new DomainError("VALIDATION_FAILED");
  const attempt = Number(row.attempt);
  if (!Number.isInteger(attempt) || attempt < 1)
    throw new DomainError("VALIDATION_FAILED");
  if (row.status === "in_progress") {
    if (
      typeof row.lease_token !== "string" ||
      typeof row.lease_expires_at !== "string" ||
      row.lease_token !==
        retrievalLeaseToken(
          row.retrieval_id,
          attempt,
          retrievalLeaseStart(row.lease_expires_at),
        )
    ) {
      throw new DomainError("VALIDATION_FAILED");
    }
  } else if (row.lease_token !== null || row.lease_expires_at !== null) {
    throw new DomainError("VALIDATION_FAILED");
  }
  return {
    retrievalId: row.retrieval_id,
    generation,
    citation: row.citation,
    selectedAt: row.selected_at,
    selectionIntegrityHash: row.selection_integrity_hash,
    attempt,
    ...(typeof row.lease_token === "string"
      ? { leaseToken: row.lease_token }
      : {}),
    ...(typeof row.lease_expires_at === "string"
      ? { leaseExpiresAt: row.lease_expires_at }
      : {}),
  };
}

function selectionIntegrityHash(
  retrievalId: string,
  generation: EligibleGeneration,
  citation: string,
  input: RetrievalScope,
  selectedAt: string,
): string {
  return sha256(
    canonicalJson({
      retrievalId,
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      workflowRunId: input.workflowRunId,
      correlationId: input.correlationId,
      incidentKind: generation.incidentKind,
      runbookId: generation.runbookId,
      version: generation.version,
      generationId: generation.generationId,
      indexName: generation.indexName,
      activationRevision: generation.revision,
      sourceHash: generation.sourceHash,
      generationAggregateHash: generation.aggregateHash,
      allowedActionsJson: generation.allowedActionsJson,
      citation,
      queryHash: input.queryHash,
      threshold: input.threshold.toString(),
      topK: input.topK,
      policyVersion: POLICY_VERSION,
      selectedAt,
    }),
  );
}

function successfulIntegrityHash(
  selection: PersistedSelection,
  input: RetrievalScope,
  chunks: readonly Record<string, unknown>[],
): string {
  return sha256(
    canonicalJson({
      selection: selectionIntegrityHash(
        selection.retrievalId,
        selection.generation,
        selection.citation,
        input,
        selection.selectedAt,
      ),
      runbookId: selection.generation.runbookId,
      version: selection.generation.version,
      generationId: selection.generation.generationId,
      citation: selection.citation,
      attempt: selection.attempt,
      chunks,
    }),
  );
}

function failedIntegrityHash(
  retrievalId: string,
  selectionIntegrityHash: string | null,
  errorCode: RunbookErrorCode,
  queryHash: string,
  finishedAt: string,
  status: "failed" | "manual_review",
  attempt: number,
): string {
  return sha256(
    canonicalJson({
      retrievalId,
      selection: selectionIntegrityHash,
      errorCode,
      queryHash,
      finishedAt,
      status,
      attempt,
    }),
  );
}

function canonicalCitation(runbookId: string, version: string): string {
  return `[runbook:${runbookId}@${version}]`;
}

function retrievalLeaseToken(
  retrievalId: string,
  attempt: number,
  leasedAt: string,
): string {
  return sha256(
    `runbook-retrieval-lease-v1\0${retrievalId}\0${attempt}\0${leasedAt}`,
  );
}

function retrievalLeaseExpiry(leasedAt: string): string {
  const timestamp = Date.parse(leasedAt);
  if (!Number.isFinite(timestamp)) throw new DomainError("VALIDATION_FAILED");
  return new Date(timestamp + RETRIEVAL_LEASE_MS).toISOString();
}

function retrievalLeaseStart(leaseExpiresAt: string): string {
  const timestamp = Date.parse(leaseExpiresAt);
  if (!Number.isFinite(timestamp)) throw new DomainError("VALIDATION_FAILED");
  return new Date(timestamp - RETRIEVAL_LEASE_MS).toISOString();
}

async function assertCurrentSelection(
  tx: StoreTransaction,
  generation: EligibleGeneration,
): Promise<void> {
  const current = await tx.execute({
    sql: `SELECT a.generation_id, a.revision, g.index_name, g.chunk_count,
      g.aggregate_hash, g.state, v.source_hash, v.allowed_actions_json,
      v.declared_status FROM runbook_activations a
      JOIN runbook_generations g ON g.generation_id = a.generation_id
      JOIN runbook_versions v ON v.runbook_id = g.runbook_id AND v.version = g.version
      WHERE a.incident_kind = ?`,
    args: [generation.incidentKind],
  });
  const row = current.rows[0];
  if (
    !row ||
    row.generation_id !== generation.generationId ||
    Number(row.revision) !== generation.revision ||
    row.index_name !== generation.indexName ||
    Number(row.chunk_count) !== generation.chunkCount ||
    row.aggregate_hash !== generation.aggregateHash ||
    row.source_hash !== generation.sourceHash ||
    row.allowed_actions_json !== generation.allowedActionsJson ||
    row.state !== "active" ||
    row.declared_status !== "active"
  ) {
    throw new DomainError("CONFLICT");
  }
}

async function assertCleanupNotClaimed(
  tx: StoreTransaction,
  generationId: string,
): Promise<void> {
  const cleanup = await tx.execute({
    sql: `SELECT status FROM runbook_generation_cleanup_claims
      WHERE generation_id = ?`,
    args: [generationId],
  });
  if (cleanup.rows[0]) throw new DomainError("CONFLICT");
}

async function appendTimeline(
  tx: StoreTransaction,
  event: Readonly<{
    timelineId: string;
    type: "runbook.retrieved" | "runbook.retrieval_failed";
    now: string;
    input: Pick<
      RetrievalScope,
      "tenantId" | "incidentId" | "workflowRunId" | "correlationId"
    >;
    payload: Record<string, unknown>;
  }>,
): Promise<void> {
  const updated = await tx.execute({
    sql: `UPDATE incidents SET timeline_sequence = timeline_sequence + 1,
      updated_at = ? WHERE tenant_id = ? AND id = ? AND updated_at <= ?
      RETURNING timeline_sequence`,
    args: [event.now, event.input.tenantId, event.input.incidentId, event.now],
  });
  if (!updated.rows[0]) throw new DomainError("CONFLICT");
  await tx.execute({
    sql: `INSERT INTO timeline_events(
      id, incident_id, tenant_id, sequence, type, category, correlation_id,
      causation_id, payload_json, schema_version, occurred_at
    ) VALUES (?, ?, ?, ?, ?, 'domain', ?, ?, ?, 1, ?)`,
    args: [
      event.timelineId,
      event.input.incidentId,
      event.input.tenantId,
      Number(updated.rows[0].timeline_sequence),
      event.type,
      event.input.correlationId,
      event.input.workflowRunId,
      JSON.stringify(event.payload),
      event.now,
    ],
  });
}

function recomputeMetadataHash(metadata: RunbookChunkMetadata): string {
  const unsigned: Partial<RunbookChunkMetadata> = { ...metadata };
  delete unsigned.metadataHash;
  return sha256(canonicalJson(unsigned));
}
