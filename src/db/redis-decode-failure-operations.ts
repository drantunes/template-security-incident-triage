import { createHash } from "node:crypto";

import type { OperationalStore } from "./operational-store.js";
import { persistStandaloneDeadLetter } from "./webhook-operations.js";

/** Raw bytes are hashed and discarded in the same durable failure path. */
export async function persistRedisDecodeFailure(
  store: OperationalStore,
  input: Readonly<{
    topic: string;
    streamId: string;
    group: string;
    consumer: string;
    rawBytes: Uint8Array;
    errorCode: "EVENT_INVALID";
  }>,
): Promise<void> {
  const payloadHash = createHash("sha256").update(input.rawBytes).digest("hex");
  const createdAt = new Date().toISOString();
  const durableRef = createHash("sha256")
    .update(input.topic)
    .update("\0")
    .update(input.streamId)
    .update("\0")
    .update(input.group)
    .update("\0")
    .update(payloadHash)
    .digest("hex");
  // `outbox_events` is intentionally incident-scoped. A closed synthetic
  // incident is therefore the minimal durable parent for broker-only poison;
  // it contains no source payload and is never made actionable.
  const tenantId = "system-redis";
  const incidentId = `redis-decode-${durableRef}`;
  const outboxId = `redis-dead-letter-${durableRef}`;
  await store.transaction(async (tx) => {
    await tx.execute({
      sql: `INSERT OR IGNORE INTO redis_decode_failures(
        stream_id, topic, consumer_group, consumer_name, payload_hash,
        payload_size, error_code, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        input.streamId,
        input.topic,
        input.group,
        input.consumer,
        payloadHash,
        input.rawBytes.byteLength,
        input.errorCode,
        createdAt,
      ],
    });
    await persistStandaloneDeadLetter(tx, {
      eventType: input.topic,
      eventRef: `redis:${input.streamId}:${payloadHash}`,
      errorCode: input.errorCode,
    });
    await tx.execute({
      sql: `INSERT OR IGNORE INTO incidents(
        id, tenant_id, kind, subject_id, status, version, timeline_sequence,
        created_at, updated_at, closed_at
      ) VALUES (?, ?, 'unknown_device_login', 'redis-stream', 'closed', 0, 0, ?, ?, ?)`,
      args: [incidentId, tenantId, createdAt, createdAt, createdAt],
    });
    await tx.execute({
      sql: `INSERT OR IGNORE INTO outbox_events(
        id, type, run_id, incident_id, tenant_id, schema_version,
        correlation_id, causation_id, payload_json, occurred_at, available_at
      ) VALUES (?, 'security.dead-letter', ?, ?, ?, 1, ?, NULL, ?, ?, ?)`,
      args: [
        outboxId,
        `redis-decode-${durableRef}`,
        incidentId,
        tenantId,
        `redis-decode-${durableRef}`,
        JSON.stringify({
          sourceEventId: input.streamId,
          topic: input.topic,
          consumerGroup: input.group,
          errorCode: input.errorCode,
          payloadHash,
          payloadSize: input.rawBytes.byteLength,
        }),
        createdAt,
        createdAt,
      ],
    });
  });
}

/**
 * XAUTOCLAIM can report a PEL ID whose stream entry was already trimmed. The
 * payload is unavailable by definition, so persist only its durable identity
 * and terminal audit/outbox record; never fabricate or retain raw bytes.
 */
export async function persistRedisClaimDeleted(
  store: OperationalStore,
  input: Readonly<{
    topic: string;
    streamId: string;
    group: string;
    consumer: string;
    errorCode: "STREAM_ENTRY_TRIMMED";
  }>,
): Promise<void> {
  const createdAt = new Date().toISOString();
  const durableRef = createHash("sha256")
    .update(input.topic)
    .update("\0")
    .update(input.streamId)
    .update("\0")
    .update(input.group)
    .digest("hex");
  const tenantId = "system-redis";
  const incidentId = `redis-decode-${durableRef}`;
  await store.transaction(async (tx) => {
    await persistStandaloneDeadLetter(tx, {
      eventType: input.topic,
      eventRef: `redis-tombstone:${input.streamId}:${durableRef}`,
      errorCode: input.errorCode,
    });
    await tx.execute({
      sql: `INSERT OR IGNORE INTO incidents(
        id, tenant_id, kind, subject_id, status, version, timeline_sequence,
        created_at, updated_at, closed_at
      ) VALUES (?, ?, 'unknown_device_login', 'redis-stream', 'closed', 0, 0, ?, ?, ?)`,
      args: [incidentId, tenantId, createdAt, createdAt, createdAt],
    });
    await tx.execute({
      sql: `INSERT OR IGNORE INTO outbox_events(
        id, type, run_id, incident_id, tenant_id, schema_version,
        correlation_id, causation_id, payload_json, occurred_at, available_at
      ) VALUES (?, 'security.dead-letter', ?, ?, ?, 1, ?, NULL, ?, ?, ?)`,
      args: [
        `redis-tombstone-${durableRef}`,
        `redis-decode-${durableRef}`,
        incidentId,
        tenantId,
        `redis-decode-${durableRef}`,
        JSON.stringify({
          sourceEventId: input.streamId,
          topic: input.topic,
          consumerGroup: input.group,
          errorCode: input.errorCode,
          payloadAvailable: false,
        }),
        createdAt,
        createdAt,
      ],
    });
  });
}
