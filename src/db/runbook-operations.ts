import { DomainError } from "../domain/errors.js";
import type { IncidentKind } from "../schemas/incident.js";
import type { PreparedChunk } from "../runbooks/chunker.js";
import { RunbookError } from "../runbooks/errors.js";
import type { LoadedRunbook } from "../runbooks/loader.js";
import {
  CHUNKING_ALGORITHM_VERSION,
  EMBEDDING_DIMENSION,
  EMBEDDING_MODEL,
  EMBEDDING_PROVIDER,
  RUNBOOK_SCHEMA_VERSION,
} from "../runbooks/schemas.js";
import type {
  OperationalStore,
  StoreTransaction,
} from "./operational-store.js";

export type EligibleGeneration = Readonly<{
  incidentKind: IncidentKind;
  runbookId: string;
  version: string;
  generationId: string;
  indexName: string;
  revision: number;
  chunkCount: number;
  aggregateHash: string;
  allowedActionsJson: string;
  sourceHash: string;
}>;

export type CleanupGenerationInput = Readonly<{
  generationId: string;
  indexName: string;
  expectedChunkCount: number;
}>;

export async function stageRunbookGeneration(
  store: OperationalStore,
  input: Readonly<{
    runbook: LoadedRunbook;
    generationId: string;
    indexName: string;
    aggregateHash: string;
    chunks: readonly PreparedChunk[];
    createdAt: string;
  }>,
): Promise<"created" | "existing"> {
  const kind = input.runbook.metadata.incidentKinds[0];
  if (!kind) throw new DomainError("VALIDATION_FAILED");
  return store.transaction(async (tx) => {
    const version = await tx.execute({
      sql: `SELECT source_hash, parsed_hash, allowed_actions_json FROM runbook_versions
        WHERE runbook_id = ? AND version = ?`,
      args: [input.runbook.metadata.id, input.runbook.metadata.version],
    });
    const allowedActionsJson = JSON.stringify(input.runbook.allowedActions);
    if (version.rows[0]) {
      if (
        version.rows[0].source_hash !== input.runbook.sourceHash ||
        version.rows[0].parsed_hash !== input.runbook.parsedHash ||
        version.rows[0].allowed_actions_json !== allowedActionsJson
      )
        throw new DomainError("CONFLICT");
    } else {
      await tx.execute({
        sql: `INSERT INTO runbook_versions(
          runbook_id, version, owner, declared_status, source_path, source_hash,
          parsed_hash, schema_version, chunking_algorithm_version,
          embedding_provider, embedding_model, embedding_dimension,
          allowed_actions_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          input.runbook.metadata.id,
          input.runbook.metadata.version,
          input.runbook.metadata.owner,
          input.runbook.metadata.status,
          input.runbook.sourcePath,
          input.runbook.sourceHash,
          input.runbook.parsedHash,
          RUNBOOK_SCHEMA_VERSION,
          CHUNKING_ALGORITHM_VERSION,
          EMBEDDING_PROVIDER,
          EMBEDDING_MODEL,
          EMBEDDING_DIMENSION,
          allowedActionsJson,
          input.createdAt,
        ],
      });
    }
    const existing = await tx.execute({
      sql: `SELECT runbook_id, version, incident_kind, index_name, state, chunk_count,
        aggregate_hash, error_code FROM runbook_generations WHERE generation_id = ?`,
      args: [input.generationId],
    });
    if (existing.rows[0]) {
      const row = existing.rows[0];
      if (
        row.runbook_id !== input.runbook.metadata.id ||
        row.version !== input.runbook.metadata.version ||
        row.incident_kind !== kind ||
        row.index_name !== input.indexName ||
        Number(row.chunk_count) !== input.chunks.length ||
        row.aggregate_hash !== input.aggregateHash ||
        !["staged", "active", "failed"].includes(String(row.state)) ||
        (row.state === "failed" &&
          row.error_code !== "RUNBOOK_BACKEND_UNAVAILABLE")
      )
        throw new DomainError("CONFLICT");
      if (row.state === "failed") {
        const cleanup = await tx.execute({
          sql: `SELECT 1 FROM runbook_generation_cleanup_claims
            WHERE generation_id = ?`,
          args: [input.generationId],
        });
        if (cleanup.rows[0]) throw new DomainError("CONFLICT");
        await tx.execute({
          sql: `UPDATE runbook_generations SET state = 'staged', error_code = NULL
            WHERE generation_id = ? AND state = 'failed'
              AND error_code = 'RUNBOOK_BACKEND_UNAVAILABLE'`,
          args: [input.generationId],
        });
      }
      return "existing";
    }
    await tx.execute({
      sql: `INSERT INTO runbook_generations(
        generation_id, runbook_id, version, incident_kind, index_name, state,
        chunk_count, aggregate_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, 'staged', ?, ?, ?)`,
      args: [
        input.generationId,
        input.runbook.metadata.id,
        input.runbook.metadata.version,
        kind,
        input.indexName,
        input.chunks.length,
        input.aggregateHash,
        input.createdAt,
      ],
    });
    for (const chunk of input.chunks) {
      await tx.execute({
        sql: `INSERT INTO runbook_chunks(
          generation_id, chunk_id, vector_id, runbook_id, version, incident_kind,
          section_key, section_ordinal, chunk_ordinal, text, content_hash,
          metadata_hash, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          input.generationId,
          chunk.id,
          chunk.metadata.vectorId,
          input.runbook.metadata.id,
          input.runbook.metadata.version,
          kind,
          chunk.metadata.sectionKey,
          chunk.metadata.sectionOrdinal,
          chunk.metadata.chunkOrdinal,
          chunk.text,
          chunk.metadata.contentHash,
          chunk.metadata.metadataHash,
          JSON.stringify(chunk.metadata),
        ],
      });
    }
    return "created";
  });
}

export async function activateRunbookGeneration(
  store: OperationalStore,
  input: Readonly<{
    generationId: string;
    expectedRevision: number;
    activatedAt: string;
  }>,
): Promise<number> {
  return store.transaction(async (tx) => {
    const targetResult = await tx.execute({
      sql: `SELECT generation_id, runbook_id, version, incident_kind, state, chunk_count,
        EXISTS(SELECT 1 FROM runbook_generation_cleanup_claims c
          WHERE c.generation_id = runbook_generations.generation_id) AS cleanup_claimed
        FROM runbook_generations WHERE generation_id = ?`,
      args: [input.generationId],
    });
    const target = targetResult.rows[0];
    if (
      !target ||
      !["staged", "active"].includes(String(target.state)) ||
      Number(target.cleanup_claimed) !== 0
    ) {
      throw new DomainError("CONFLICT");
    }
    const indexed = await tx.execute({
      sql: `SELECT count(*) AS count FROM runbook_chunks
        WHERE generation_id = ? AND indexed_at IS NOT NULL`,
      args: [input.generationId],
    });
    if (Number(indexed.rows[0]?.count) !== Number(target.chunk_count)) {
      throw new DomainError("CONFLICT");
    }
    const current = await tx.execute({
      sql: `SELECT generation_id, revision FROM runbook_activations WHERE incident_kind = ?`,
      args: [target.incident_kind as string],
    });
    const currentRow = current.rows[0];
    if (!currentRow) {
      if (input.expectedRevision !== 0) throw new DomainError("CONFLICT");
      await tx.execute({
        sql: `INSERT INTO runbook_activations(
          incident_kind, runbook_id, version, generation_id, revision, activated_at
        ) VALUES (?, ?, ?, ?, 1, ?)`,
        args: [
          target.incident_kind as string,
          target.runbook_id as string,
          target.version as string,
          input.generationId,
          input.activatedAt,
        ],
      });
      await tx.execute({
        sql: `INSERT INTO runbook_activation_events(
          incident_kind, resulting_revision, operation, from_generation_id,
          to_generation_id, expected_revision, occurred_at
        ) VALUES (?, 1, 'activate', NULL, ?, 0, ?)`,
        args: [
          target.incident_kind as string,
          input.generationId,
          input.activatedAt,
        ],
      });
    } else {
      if (currentRow.generation_id === input.generationId) {
        return Number(currentRow.revision);
      }
      if (Number(currentRow.revision) !== input.expectedRevision)
        throw new DomainError("CONFLICT");
      const updated = await tx.execute({
        sql: `UPDATE runbook_activations SET runbook_id = ?, version = ?,
          generation_id = ?, revision = revision + 1, activated_at = ?
          WHERE incident_kind = ? AND revision = ?`,
        args: [
          target.runbook_id as string,
          target.version as string,
          input.generationId,
          input.activatedAt,
          target.incident_kind as string,
          input.expectedRevision,
        ],
      });
      if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
      await tx.execute({
        sql: `UPDATE runbook_generations SET state = 'retired', retired_at = ?
          WHERE generation_id = ? AND state = 'active'`,
        args: [input.activatedAt, currentRow.generation_id as string],
      });
      await tx.execute({
        sql: `INSERT INTO runbook_activation_events(
          incident_kind, resulting_revision, operation, from_generation_id,
          to_generation_id, expected_revision, occurred_at
        ) VALUES (?, ?, 'activate', ?, ?, ?, ?)`,
        args: [
          target.incident_kind as string,
          input.expectedRevision + 1,
          currentRow.generation_id as string,
          input.generationId,
          input.expectedRevision,
          input.activatedAt,
        ],
      });
    }
    await tx.execute({
      sql: `UPDATE runbook_generations SET state = 'active', activated_at = ?,
        retired_at = NULL, error_code = NULL WHERE generation_id = ?`,
      args: [input.activatedAt, input.generationId],
    });
    return input.expectedRevision + 1;
  });
}

export async function resolveRollbackGeneration(
  store: OperationalStore,
  generationId: string,
): Promise<EligibleGeneration> {
  const result = await store.execute({
    sql: `SELECT g.incident_kind, g.runbook_id, g.version, g.generation_id,
      g.index_name, g.chunk_count, g.aggregate_hash, g.state,
      v.allowed_actions_json, v.source_hash, v.declared_status,
      a.revision,
      EXISTS(SELECT 1 FROM runbook_activation_events e
        WHERE e.incident_kind = g.incident_kind
          AND e.to_generation_id = g.generation_id) AS was_active
      FROM runbook_generations g
      JOIN runbook_versions v ON v.runbook_id = g.runbook_id AND v.version = g.version
      JOIN runbook_activations a ON a.incident_kind = g.incident_kind
      WHERE g.generation_id = ?`,
    args: [generationId],
  });
  const row = result.rows[0];
  if (
    !row ||
    row.state !== "retired" ||
    row.declared_status !== "active" ||
    Number(row.was_active) !== 1
  ) {
    throw new DomainError("CONFLICT");
  }
  return {
    incidentKind: row.incident_kind as IncidentKind,
    runbookId: String(row.runbook_id),
    version: String(row.version),
    generationId: String(row.generation_id),
    indexName: String(row.index_name),
    revision: Number(row.revision),
    chunkCount: Number(row.chunk_count),
    aggregateHash: String(row.aggregate_hash),
    allowedActionsJson: String(row.allowed_actions_json),
    sourceHash: String(row.source_hash),
  };
}

export async function rollbackRunbookGenerationCas(
  store: OperationalStore,
  input: Readonly<{
    generationId: string;
    expectedRevision: number;
    rolledBackAt: string;
  }>,
): Promise<number> {
  return store.transaction(async (tx) => {
    const targetResult = await tx.execute({
      sql: `SELECT g.runbook_id, g.version, g.incident_kind, g.state, g.chunk_count,
        (SELECT count(*) FROM runbook_chunks c WHERE c.generation_id = g.generation_id
          AND c.indexed_at IS NOT NULL) AS indexed_count,
        EXISTS(SELECT 1 FROM runbook_activation_events e
          WHERE e.incident_kind = g.incident_kind
            AND e.to_generation_id = g.generation_id) AS was_active,
        EXISTS(SELECT 1 FROM runbook_generation_cleanup_claims c
          WHERE c.generation_id = g.generation_id) AS cleanup_claimed
        FROM runbook_generations g WHERE g.generation_id = ?`,
      args: [input.generationId],
    });
    const target = targetResult.rows[0];
    if (
      !target ||
      target.state !== "retired" ||
      Number(target.indexed_count) !== Number(target.chunk_count) ||
      Number(target.was_active) !== 1 ||
      Number(target.cleanup_claimed) !== 0
    ) {
      throw new DomainError("CONFLICT");
    }
    const currentResult = await tx.execute({
      sql: `SELECT generation_id, revision FROM runbook_activations
        WHERE incident_kind = ?`,
      args: [target.incident_kind as string],
    });
    const current = currentResult.rows[0];
    if (
      !current ||
      current.generation_id === input.generationId ||
      Number(current.revision) !== input.expectedRevision
    ) {
      throw new DomainError("CONFLICT");
    }
    const revision = input.expectedRevision + 1;
    const updated = await tx.execute({
      sql: `UPDATE runbook_activations SET runbook_id = ?, version = ?,
        generation_id = ?, revision = ?, activated_at = ?
        WHERE incident_kind = ? AND revision = ? AND generation_id = ?`,
      args: [
        target.runbook_id as string,
        target.version as string,
        input.generationId,
        revision,
        input.rolledBackAt,
        target.incident_kind as string,
        input.expectedRevision,
        current.generation_id as string,
      ],
    });
    if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
    await tx.execute({
      sql: `UPDATE runbook_generations SET state = 'retired', retired_at = ?
        WHERE generation_id = ? AND state = 'active'`,
      args: [input.rolledBackAt, current.generation_id as string],
    });
    const activated = await tx.execute({
      sql: `UPDATE runbook_generations SET state = 'active', activated_at = ?,
        retired_at = NULL, error_code = NULL
        WHERE generation_id = ? AND state = 'retired'`,
      args: [input.rolledBackAt, input.generationId],
    });
    if (activated.rowsAffected !== 1) throw new DomainError("CONFLICT");
    await tx.execute({
      sql: `INSERT INTO runbook_activation_events(
        incident_kind, resulting_revision, operation, from_generation_id,
        to_generation_id, expected_revision, occurred_at
      ) VALUES (?, ?, 'rollback', ?, ?, ?, ?)`,
      args: [
        target.incident_kind as string,
        revision,
        current.generation_id as string,
        input.generationId,
        input.expectedRevision,
        input.rolledBackAt,
      ],
    });
    return revision;
  });
}

export async function claimRunbookGenerationCleanup(
  store: OperationalStore,
  input: CleanupGenerationInput,
  claimedAt: string,
  dryRun: boolean,
): Promise<"claimed" | "deleted" | "validated"> {
  return store.transaction(async (tx) => {
    await assertCleanupEligible(tx, input, claimedAt);
    const existing = await tx.execute({
      sql: `SELECT index_name, expected_chunk_count, status
        FROM runbook_generation_cleanup_claims WHERE generation_id = ?`,
      args: [input.generationId],
    });
    if (existing.rows[0]) {
      const row = existing.rows[0];
      if (
        row.index_name !== input.indexName ||
        Number(row.expected_chunk_count) !== input.expectedChunkCount
      ) {
        throw new DomainError("CONFLICT");
      }
      return row.status === "deleted" ? "deleted" : "claimed";
    }
    if (dryRun) return "validated";
    await tx.execute({
      sql: `INSERT INTO runbook_generation_cleanup_claims(
        generation_id, index_name, expected_chunk_count, status, claimed_at
      ) VALUES (?, ?, ?, 'claimed', ?)`,
      args: [
        input.generationId,
        input.indexName,
        input.expectedChunkCount,
        claimedAt,
      ],
    });
    return "claimed";
  });
}

export async function revalidateRunbookGenerationCleanup(
  store: OperationalStore,
  input: CleanupGenerationInput,
  checkedAt: string,
): Promise<void> {
  await store.transaction(async (tx) => {
    await assertCleanupEligible(tx, input, checkedAt);
    const claim = await tx.execute({
      sql: `SELECT index_name, expected_chunk_count, status
        FROM runbook_generation_cleanup_claims WHERE generation_id = ?`,
      args: [input.generationId],
    });
    const row = claim.rows[0];
    if (
      !row ||
      row.status !== "claimed" ||
      row.index_name !== input.indexName ||
      Number(row.expected_chunk_count) !== input.expectedChunkCount
    ) {
      throw new DomainError("CONFLICT");
    }
  });
}

export async function completeRunbookGenerationCleanup(
  store: OperationalStore,
  input: CleanupGenerationInput,
  completedAt: string,
): Promise<void> {
  await store.transaction(async (tx) => {
    const updated = await tx.execute({
      sql: `UPDATE runbook_generation_cleanup_claims
        SET status = 'deleted', completed_at = ?
        WHERE generation_id = ? AND index_name = ? AND expected_chunk_count = ?
          AND status = 'claimed'`,
      args: [
        completedAt,
        input.generationId,
        input.indexName,
        input.expectedChunkCount,
      ],
    });
    if (updated.rowsAffected !== 1) throw new DomainError("CONFLICT");
  });
}

async function assertCleanupEligible(
  tx: StoreTransaction,
  input: CleanupGenerationInput,
  checkedAt: string,
): Promise<void> {
  const result = await tx.execute({
    sql: `SELECT g.index_name, g.state, g.chunk_count,
      EXISTS(SELECT 1 FROM runbook_activations a
        WHERE a.generation_id = g.generation_id) AS is_active,
      EXISTS(SELECT 1 FROM runbook_retrievals r
        WHERE r.generation_id = g.generation_id
          AND r.status = 'in_progress' AND r.lease_expires_at > ?) AS has_in_progress
      FROM runbook_generations g WHERE g.generation_id = ?`,
    args: [checkedAt, input.generationId],
  });
  const row = result.rows[0];
  if (
    !row ||
    row.index_name !== input.indexName ||
    !["failed", "retired"].includes(String(row.state)) ||
    Number(row.chunk_count) !== input.expectedChunkCount ||
    Number(row.is_active) !== 0 ||
    Number(row.has_in_progress) !== 0
  ) {
    throw new DomainError("CONFLICT");
  }
}

export async function markRunbookChunksIndexed(
  store: OperationalStore,
  generationId: string,
  indexedAt: string,
): Promise<void> {
  await store.transaction(async (tx) => {
    await tx.execute({
      sql: `UPDATE runbook_chunks SET indexed_at = COALESCE(indexed_at, ?)
        WHERE generation_id = ?`,
      args: [indexedAt, generationId],
    });
  });
}

export async function markRunbookGenerationFailed(
  store: OperationalStore,
  generationId: string,
  errorCode:
    | "RUNBOOK_BACKEND_UNAVAILABLE"
    | "RUNBOOK_INELIGIBLE"
    | "RUNBOOK_INTEGRITY_FAILED",
): Promise<void> {
  await store.transaction(async (tx) => {
    await tx.execute({
      sql: `UPDATE runbook_generations SET state = 'failed', error_code = ?
        WHERE generation_id = ? AND state = 'staged'`,
      args: [errorCode, generationId],
    });
  });
}

export async function getActivationRevision(
  store: OperationalStore,
  kind: IncidentKind,
): Promise<number> {
  const result = await store.execute({
    sql: "SELECT revision FROM runbook_activations WHERE incident_kind = ?",
    args: [kind],
  });
  return result.rows[0] ? Number(result.rows[0].revision) : 0;
}

export async function resolveEligibleGeneration(
  store: OperationalStore,
  kind: IncidentKind,
): Promise<EligibleGeneration | undefined> {
  const result = await store.execute({
    sql: `SELECT a.incident_kind, a.runbook_id, a.version, a.generation_id,
      a.revision, g.index_name, g.chunk_count, g.aggregate_hash,
      g.state, v.declared_status, v.allowed_actions_json, v.source_hash
      FROM runbook_activations a
      JOIN runbook_generations g ON g.generation_id = a.generation_id
        AND g.runbook_id = a.runbook_id AND g.version = a.version
        AND g.incident_kind = a.incident_kind
      JOIN runbook_versions v ON v.runbook_id = a.runbook_id AND v.version = a.version
      WHERE a.incident_kind = ?`,
    args: [kind],
  });
  if (result.rows.length === 0) return undefined;
  if (result.rows.length !== 1) throw new RunbookError("RUNBOOK_AMBIGUOUS");
  const row = result.rows[0];
  if (row?.state !== "active" || row.declared_status !== "active")
    throw new DomainError("CONFLICT");
  return {
    incidentKind: row.incident_kind as IncidentKind,
    runbookId: String(row.runbook_id),
    version: String(row.version),
    generationId: String(row.generation_id),
    indexName: String(row.index_name),
    revision: Number(row.revision),
    chunkCount: Number(row.chunk_count),
    aggregateHash: String(row.aggregate_hash),
    allowedActionsJson: String(row.allowed_actions_json),
    sourceHash: String(row.source_hash),
  };
}
