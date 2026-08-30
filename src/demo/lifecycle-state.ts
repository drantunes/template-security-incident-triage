import { semanticDatabaseHash, writeJournal } from "./journal.js";
import type { DemoJournal, DemoRecord } from "./contracts.js";

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error("DEMO_INTERRUPTED");
}

export function throwIfDeadlineExceeded(deadline: number | undefined): void {
  if (deadline !== undefined && performance.now() > deadline)
    throw new Error("DEMO_AWAITING_APPROVAL_TIMEOUT");
}

export async function transition(
  root: string,
  journal: DemoJournal,
  state: DemoJournal["state"],
  resources = journal.resources,
  fields: Partial<
    Pick<DemoJournal, "incidentId" | "workflowRunId" | "approvalId" | "planId">
  > = {},
  options: Readonly<{ refreshDatabaseHash?: boolean }> = {},
): Promise<DemoJournal> {
  const synchronizedResources = await Promise.all(
    resources.map(async (resource) => {
      if (resource.kind !== "local_database") return resource;
      if (
        resource.expectedHash.startsWith("pending:") ||
        resource.expectedHash.startsWith("reserved:") ||
        options.refreshDatabaseHash === false
      )
        return resource;
      return {
        ...resource,
        expectedHash: await semanticDatabaseHash(journal.databasePath),
      };
    }),
  );
  return writeJournal(root, journal, {
    schemaVersion: 1,
    demoRunId: journal.demoRunId,
    scenario: journal.scenario,
    mode: "mock",
    runKeyHash: journal.runKeyHash,
    state,
    createdAt: journal.createdAt,
    databasePath: journal.databasePath,
    resources: synchronizedResources,
    ...(journal.incidentId ? { incidentId: journal.incidentId } : {}),
    ...(journal.workflowRunId ? { workflowRunId: journal.workflowRunId } : {}),
    ...(journal.approvalId ? { approvalId: journal.approvalId } : {}),
    ...(journal.planId ? { planId: journal.planId } : {}),
    ...fields,
  });
}

export async function refreshDatabaseHash(
  root: string,
  journal: DemoJournal,
): Promise<DemoJournal> {
  const resources = await Promise.all(
    journal.resources.map(async (resource) =>
      resource.kind === "local_database"
        ? {
            ...resource,
            expectedHash: await semanticDatabaseHash(journal.databasePath),
          }
        : resource,
    ),
  );
  return transition(root, journal, journal.state, resources);
}

export function record(
  journal: DemoJournal,
  type: DemoRecord["type"],
  extra: Partial<DemoRecord> = {},
): DemoRecord {
  return {
    schemaVersion: 1,
    type,
    demoRunId: journal.demoRunId,
    scenario: journal.scenario,
    mode: journal.mode,
    state: journal.state,
    occurredAt: journal.updatedAt,
    ...(journal.incidentId ? { incidentId: journal.incidentId } : {}),
    ...(journal.workflowRunId ? { workflowRunId: journal.workflowRunId } : {}),
    ...(journal.approvalId ? { approvalId: journal.approvalId } : {}),
    ...(journal.planId ? { planId: journal.planId } : {}),
    ...extra,
  };
}

export function pendingDatabasePrecondition(demoRunId: string): string {
  return `pending:${demoRunId}`;
}

export function reservedDatabasePrecondition(hash: string): string {
  return `reserved:${hash}`;
}
