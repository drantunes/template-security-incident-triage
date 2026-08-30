/**
 * Public façade for the Phase 9 demo lifecycle. Each concern lives behind a
 * dedicated internal boundary; this module intentionally owns no provider,
 * cleanup, decision, or verification policy.
 */
import { cleanupDemo as cleanupOwnedDemo } from "./cleanup.js";
import { type DemoJournal } from "./contracts.js";
import { demoRoot, readJournal } from "./journal.js";
import { decideMockDemo } from "./runner-decision.js";

export { runMockDemo } from "./runner-lifecycle.js";
export type { DemoRunResult, RunOptions } from "./runner-types.js";
export { verifyDemoSurfaceProjection } from "./runner-verification.js";

export async function inspectDemo(
  root: string | undefined,
  demoRunId: string,
): Promise<DemoJournal | undefined> {
  return readJournal(demoRoot(root), demoRunId);
}

export async function cleanupDemo(
  root: string | undefined,
  demoRunId: string,
): Promise<DemoJournal> {
  return cleanupOwnedDemo(demoRoot(root), demoRunId);
}

export { decideMockDemo };
