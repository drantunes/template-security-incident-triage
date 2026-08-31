import {
  readJournal,
  removeOwnedDatabase,
  removeOwnedTraceDatabase,
  resourceHash,
  semanticDatabaseHash,
} from "./journal.js";
import type { DemoJournal } from "./contracts.js";
import { pendingDatabasePrecondition, transition } from "./lifecycle-state.js";

export async function cleanupDemo(
  root: string,
  demoRunId: string,
): Promise<DemoJournal> {
  const journal = await readJournal(root, demoRunId);
  if (!journal) throw new Error("DEMO_RUN_NOT_FOUND");
  if (journal.state === "cleaned") return journal;
  if (journal.state === "cleaning")
    return await awaitConcurrentCleanup(root, demoRunId);
  let cleaning: DemoJournal;
  try {
    cleaning = await transition(
      root,
      journal,
      "cleaning",
      journal.resources,
      {},
      { refreshDatabaseHash: false },
    );
  } catch (error) {
    if (error instanceof Error && error.message === "DEMO_JOURNAL_CAS_CONFLICT")
      return await awaitConcurrentCleanup(root, demoRunId);
    throw error;
  }
  try {
    await removeOwnedDatabase(root, cleaning, {
      verifyPrecondition: (resource, databasePath) =>
        verifyDatabasePrecondition(
          cleaning,
          resource.expectedHash,
          databasePath,
        ),
    });
    await removeOwnedTraceDatabase(root, cleaning);
    return transition(
      root,
      cleaning,
      "cleaned",
      cleaning.resources,
      {},
      { refreshDatabaseHash: false },
    );
  } catch (error) {
    try {
      await transition(
        root,
        cleaning,
        "cleanup_blocked",
        cleaning.resources,
        {},
        { refreshDatabaseHash: false },
      );
    } catch (transitionError) {
      if (
        !(transitionError instanceof Error) ||
        transitionError.message !== "DEMO_JOURNAL_CAS_CONFLICT"
      )
        throw transitionError;
      return await awaitConcurrentCleanup(root, demoRunId);
    }
    throw error;
  }
}

async function awaitConcurrentCleanup(
  root: string,
  demoRunId: string,
): Promise<DemoJournal> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const current = await readJournal(root, demoRunId);
    if (!current) throw new Error("DEMO_RUN_NOT_FOUND");
    if (current.state === "cleaned") return current;
    if (current.state !== "cleaning") {
      if (current.state === "cleanup_blocked")
        throw new Error("DEMO_CLEANUP_PRECONDITION_FAILED");
      return cleanupDemo(root, demoRunId);
    }
    await new Promise<void>((done) => setTimeout(done, 10));
  }
  throw new Error("DEMO_CLEANUP_IN_PROGRESS");
}

async function verifyDatabasePrecondition(
  journal: DemoJournal,
  expectedHash: string,
  databasePath: string,
): Promise<boolean> {
  if (expectedHash === pendingDatabasePrecondition(journal.demoRunId))
    return false;
  if (expectedHash.startsWith("reserved:"))
    return (
      (await resourceHash(databasePath)) ===
      expectedHash.slice("reserved:".length)
    );
  return (await semanticDatabaseHash(databasePath)) === expectedHash;
}
