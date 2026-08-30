import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import type { DashboardPrincipal } from "../auth/dashboard-principal.js";
import { createReadOnlyLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { readDashboardIncident } from "../dashboard/queries.js";
import { validateSseReplay } from "../dashboard/sse.js";

import type { DemoJournal } from "./contracts.js";
import { demoId, fixtureForScenario } from "./fixtures.js";
import {
  assertDemoObservationPreconditions,
  semanticDatabaseHash,
} from "./journal.js";
import { verifyDemoSurfaceProjection } from "./runner.js";

/**
 * Local, versioned observer for the existing Phase 7 dashboard read model and
 * SSE replay boundary. It deliberately does not register an HTTP route or
 * manufacture a dashboard cookie: the supplied principal is a fixture-scoped
 * mock identity used only to exercise the same tenant authorization input
 * consumed by those exported F7 interfaces.
 */
export async function observeDemoSurfaces(
  journal: DemoJournal,
  root = resolve(journal.databasePath, ".."),
) {
  if (!journal.incidentId || !journal.workflowRunId || !journal.approvalId)
    throw new Error("DEMO_IDS_MISSING");
  const resource = await assertDemoObservationPreconditions(root, journal);
  // This uses a fresh read-only client only after the lifecycle, ownership and
  // file-type gates have passed. A semantic mismatch is reported before any
  // DTO/SSE value can escape this adapter.
  if (
    (await semanticDatabaseHash(journal.databasePath)) !== resource.expectedHash
  )
    throw new Error("DEMO_SURFACE_PRECONDITION_FAILED");
  const tenantId = fixtureForScenario(
    journal.scenario,
    journal.demoRunId,
  ).tenantId;
  const principal: DashboardPrincipal = {
    userRef: demoId("dashboard-user", journal.demoRunId),
    tenantId,
    organizationId: tenantId,
    role: "soc_manager",
    sessionRef: demoId("dashboard-session", journal.demoRunId),
  };
  const store = createReadOnlyLibSqlOperationalStore({
    url: pathToFileURL(journal.databasePath).href,
  });
  try {
    await verifyDemoSurfaceProjection(store, journal);
    // The dashboard DTO itself holds a snapshot transaction. Keep the other
    // read-only queries outside it so the embedded client never interleaves a
    // second connection operation with that snapshot.
    const dashboard = await readDashboardIncident(store, {
      tenantId: principal.tenantId,
      incidentId: journal.incidentId,
    });
    const replay = await validateSseReplay(
      store,
      principal,
      journal.incidentId,
      undefined,
    );
    const workflow = await store.execute({
      sql: `SELECT workflow_id, run_id, status, incident_id
        FROM workflow_runs WHERE run_id = ? AND incident_id = ?`,
      args: [journal.workflowRunId, journal.incidentId],
    });
    const row = workflow.rows[0];
    if (!replay || !row || row.run_id !== journal.workflowRunId)
      throw new Error("DEMO_SURFACE_PROJECTION_DIVERGED");
    if (
      (await semanticDatabaseHash(journal.databasePath)) !==
      resource.expectedHash
    )
      throw new Error("DEMO_SURFACE_PRECONDITION_FAILED");
    return {
      schemaVersion: 1 as const,
      type: "surface_observation" as const,
      demoRunId: journal.demoRunId,
      scenario: journal.scenario,
      mode: journal.mode,
      state: journal.state,
      occurredAt: journal.updatedAt,
      ids: {
        incidentId: journal.incidentId,
        workflowRunId: journal.workflowRunId,
        approvalId: journal.approvalId,
        planId: journal.planId ?? null,
      },
      /** F7's tenant-scoped dashboard detail DTO, not a raw SQL projection. */
      dashboard,
      /** F7's strict, tenant-scoped SSE replay result, before HTTP framing. */
      sse: {
        after: replay.after,
        events: replay.events,
      },
      /** Stable local equivalent for the unavailable Studio UI. */
      mastraRun: {
        workflowId: String(row.workflow_id),
        workflowRunId: String(row.run_id),
        incidentId: String(row.incident_id),
        status: String(row.status),
      },
    };
  } finally {
    store.close();
  }
}
