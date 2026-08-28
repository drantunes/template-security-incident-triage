import { describe, expect, it } from "vitest";

import { decodeCursor, encodeCursor } from "../../src/dashboard/contracts.js";
import {
  redactTimelinePayload,
  safeExternalUrl,
} from "../../src/dashboard/redaction.js";
import { parseLastEventId } from "../../src/dashboard/sse.js";

describe("Phase 7 dashboard projections and SSE", () => {
  it("redacts forbidden timeline data by construction", () => {
    expect(
      redactTimelinePayload({
        status: "approved",
        rawPayloadRef: "secret",
        token: "abc",
        nested: { value: 1 },
      }),
    ).toEqual({ status: "approved" });
  });
  it("uses tenant-bound opaque cursors and rejects malformed cursors", () => {
    const cursor = encodeCursor(
      {
        updatedAt: "2026-08-28T00:00:00.000Z",
        incidentId: "incident_123",
        tenantId: "tenant_123",
        filters: "{}",
      },
      "c".repeat(32),
    );
    expect(
      decodeCursor(
        cursor,
        { tenantId: "tenant_123", filters: "{}" },
        "c".repeat(32),
      ),
    ).toEqual({
      updatedAt: "2026-08-28T00:00:00.000Z",
      incidentId: "incident_123",
    });
    expect(
      decodeCursor(
        cursor,
        { tenantId: "tenant_other", filters: "{}" },
        "c".repeat(32),
      ),
    ).toBeNull();
    expect(
      decodeCursor(
        `${cursor}x`,
        { tenantId: "tenant_123", filters: "{}" },
        "c".repeat(32),
      ),
    ).toBeNull();
    expect(
      decodeCursor(
        "not-a-cursor",
        { tenantId: "tenant_123", filters: "{}" },
        "c".repeat(32),
      ),
    ).toBeNull();
  });
  it("accepts only a current incident's monotonic SSE identifiers", () => {
    expect(parseLastEventId("incident_123", "incident_123:4")).toBe(4);
    expect(parseLastEventId("incident_123", "other:4")).toBeNull();
    expect(parseLastEventId("incident_123", "incident_123:0")).toBeNull();
    expect(safeExternalUrl("https://linear.app/team/SEC-1")).toBe(
      "https://linear.app/team/SEC-1",
    );
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
  });
});
