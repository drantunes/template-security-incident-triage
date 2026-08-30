import { z } from "zod";

export const DemoScenarioSchema = z.enum(["privilege", "country", "device"]);
export type DemoScenario = z.infer<typeof DemoScenarioSchema>;

export const DemoModeSchema = z.enum(["mock", "staging", "production"]);
export type DemoMode = z.infer<typeof DemoModeSchema>;

export const DemoCommandSchema = z.enum([
  "run",
  "inspect",
  "cleanup",
  "preflight",
]);
export type DemoCommand = z.infer<typeof DemoCommandSchema>;

export const DEMO_EXIT = Object.freeze({
  ok: 0,
  usage: 2,
  preflight: 3,
  approval: 4,
  timeout: 5,
  functional: 6,
  verification: 7,
  cleanup: 8,
  provider: 9,
  interrupted: 130,
});

/** Maps every emitted demo reason family to its stable CLI contract code. */
export function exitForDemoError(code: string): number {
  if (code.includes("TIMEOUT")) return DEMO_EXIT.timeout;
  if (code === "DEMO_INTERRUPTED") return DEMO_EXIT.interrupted;
  if (
    code.includes("CLEANUP") ||
    code === "DEMO_RUN_NOT_FOUND" ||
    code.includes("JOURNAL_") ||
    code.includes("DATABASE_")
  )
    return DEMO_EXIT.cleanup;
  if (code.includes("APPROVAL") || code.includes("DECISION"))
    return DEMO_EXIT.approval;
  if (
    code.includes("PROVIDER") ||
    code.includes("OUTBOX") ||
    code.includes("WEBHOOK") ||
    code.includes("BASELINE")
  )
    return DEMO_EXIT.provider;
  if (
    code.includes("RUN_KEY") ||
    code.includes("RECOVERY") ||
    code.includes("IDS_MISSING")
  )
    return DEMO_EXIT.functional;
  return DEMO_EXIT.verification;
}

export type DemoRecord = Readonly<{
  schemaVersion: 1;
  type:
    | "preflight"
    | "seed"
    | "trigger"
    | "state"
    | "approval_required"
    | "terminal"
    | "verification"
    | "cleanup"
    | "error";
  demoRunId: string;
  scenario: DemoScenario;
  mode: DemoMode;
  state: string;
  occurredAt: string;
  incidentId?: string;
  workflowRunId?: string;
  approvalId?: string;
  planId?: string;
  safeRef?: string;
  code?: string;
  nextCommand?: string;
  runbookId?: string;
  severity?: "low" | "medium" | "high";
  actionTypes?: readonly string[];
  verificationRef?: string;
  outcome?: "approved" | "rejected" | "expired" | "contained" | "failed";
}>;

/** Error records intentionally model unavailable identifiers as null, rather
 * than inventing a scenario/run id that an automation could mistake for fact. */
export const DemoErrorRecordSchema = z
  .object({
    schemaVersion: z.literal(1),
    type: z.literal("error"),
    demoRunId: z.string().nullable(),
    scenario: DemoScenarioSchema.nullable(),
    mode: DemoModeSchema.nullable(),
    state: z.literal("error"),
    occurredAt: z.string().datetime(),
    code: z.string().regex(/^DEMO_[A-Z0-9_]+$/u),
  })
  .strict();
export type DemoErrorRecord = z.infer<typeof DemoErrorRecordSchema>;

export type DemoJournal = Readonly<{
  schemaVersion: 1;
  revision: number;
  checksum: string;
  demoRunId: string;
  scenario: DemoScenario;
  mode: "mock";
  runKeyHash: string;
  state:
    | "prepared"
    | "seeding"
    | "seeded"
    | "triggered"
    | "awaiting_approval"
    | "decided"
    | "terminal"
    | "interrupted"
    | "timed_out"
    | "failed"
    | "cleaning"
    | "cleaned"
    | "cleanup_failed"
    | "cleanup_blocked";
  createdAt: string;
  updatedAt: string;
  databasePath: string;
  /** Isolated Mastra observability domain for this local run. */
  traceDatabasePath: string;
  incidentId?: string;
  workflowRunId?: string;
  approvalId?: string;
  planId?: string;
  resources: readonly Readonly<{
    kind:
      | "local_database"
      | "local_trace_database"
      | "mock_role"
      | "mock_session"
      | "mock_device"
      | "mock_reauthentication";
    ref: string;
    ownership: "created" | "mutated" | "irreversible";
    /** SHA-256 of the owned resource after the last authoritative observation. */
    expectedHash: string;
  }>[];
}>;

export type DemoPreflight = Readonly<{
  ok: boolean;
  code?: string;
  mode: DemoMode;
  capabilities: Readonly<
    Record<string, "supported" | "unsupported" | "blocked">
  >;
  operations: readonly string[];
}>;
