import { createHash } from "node:crypto";

import { z } from "zod";

import type { OperationalStore } from "../db/operational-store.js";
import type { AnalyticsRecord } from "./analytics-store.js";

const journalSchema = z
  .object({
    sequence: z.coerce.number().int().positive(),
    source: z.enum([
      "timeline_events",
      "provider_deliveries",
      "approvals",
      "eval_results",
    ]),
    source_id: z.string().min(1),
    source_version: z.string().min(1),
    changed_at: z.string().datetime(),
    snapshot_json: z.string().min(2),
  })
  .strict();
const publicRowSchema = z
  .object({
    id: z.string().min(1),
    tenant_id: z.string().min(1),
    incident_id: z.string().nullable().optional(),
    occurred_at: z.string().datetime().optional(),
    category: z.string().optional(),
    status: z.string().nullable().optional(),
    scenario: z.enum(["privilege", "country", "device"]).nullable().optional(),
  })
  .strict();

/** Reads only the public journal and a strict projection of its four sources. */
export async function exportAnalyticsSince(
  store: OperationalStore,
  cursor: number,
  limit = 500,
): Promise<readonly AnalyticsRecord[]> {
  if (
    !Number.isSafeInteger(cursor) ||
    cursor < 0 ||
    !Number.isSafeInteger(limit) ||
    limit < 1
  )
    throw new Error("PHASE10_ANALYTICS_CURSOR_INVALID");
  const output: AnalyticsRecord[] = [];
  // A v9 historical terminal row can be intentionally withheld below because
  // it has no authoritative timestamp. Continue scanning raw pages so a gap
  // cannot hide later valid rows or stall a cursor-based consumer.
  let rawCursor = cursor;
  for (;;) {
    const journal = await store.execute({
      sql: "SELECT sequence,source,source_id,source_version,changed_at,snapshot_json FROM analytics_export_events WHERE sequence > ? ORDER BY sequence LIMIT ?",
      args: [rawCursor, limit],
    });
    if (!journal.rows.length) break;
    for (const raw of journal.rows) {
      const event = journalSchema.parse(raw);
      rawCursor = event.sequence;
      // The snapshot is materialised in the append-only event; reading a mutable
      // source row here would rewrite historical retries/approvals during export.
      const row = publicRowSchema.parse(
        JSON.parse(event.snapshot_json) as unknown,
      );
      if (row.id !== event.source_id)
        throw new Error("PHASE10_ANALYTICS_SNAPSHOT_INVALID");
      if (!row.occurred_at || !row.category)
        throw new Error("PHASE10_ANALYTICS_SOURCE_INVALID");
      // Version 9 could only reconstruct a provider terminal timestamp as the
      // explicit 1970 sentinel. Keep that immutable journal row for audit, but
      // never promote it into an authoritative metric sample.
      if (
        event.source === "provider_deliveries" &&
        row.occurred_at === "1970-01-01T00:00:00.000Z"
      )
        continue;
      output.push({
        sequence: event.sequence,
        source: event.source,
        sourceId: row.id,
        // `source_version` describes the mutable producer state and can repeat
        // for a legitimate update (for example external_ref changes while a
        // provider remains pending). The append-only journal sequence is the
        // authoritative monotonic version for the read model.
        sourceVersion: `${event.source_version}@${event.sequence}`,
        tenantId: row.tenant_id,
        incidentId: row.incident_id ?? undefined,
        occurredAt: row.occurred_at,
        category: row.category,
        status: row.status ?? undefined,
        scenario: row.scenario ?? undefined,
        checksum: createHash("sha256")
          .update(event.snapshot_json, "utf8")
          .digest("hex"),
      });
      if (output.length === limit) return Object.freeze(output);
    }
    if (journal.rows.length < limit) break;
  }
  return Object.freeze(output);
}

/** A deterministic full journal scan used for rebuild verification only. */
export async function exportAllAnalytics(
  store: OperationalStore,
  pageSize = 500,
): Promise<readonly AnalyticsRecord[]> {
  const output: AnalyticsRecord[] = [];
  let cursor = 0;
  for (;;) {
    const page = await exportAnalyticsSince(store, cursor, pageSize);
    if (!page.length) return Object.freeze(output);
    output.push(...page);
    cursor = page.at(-1)!.sequence;
  }
}
