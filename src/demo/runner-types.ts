import type { DemoJournal, DemoRecord, DemoScenario } from "./contracts.js";
import type { StructuredLogger } from "../logging.js";

export type RunOptions = Readonly<{
  scenario: DemoScenario;
  runKey: string;
  root?: string;
  decision?: "approve" | "reject" | "expire";
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Optional product logger used by the report's real-sink redaction gate. */
  logger?: StructuredLogger;
  /** Isolated runbook fixture root used by Phase 10 redaction-source tests. */
  runbookRoot?: string;
  /** Raw test-only sources; production demo callers leave this undefined. */
  redactionSources?: Readonly<{
    alert?: string;
    evidence?: string;
    provider?: string;
    approvalComment?: string;
    approvalActor?: string;
  }>;
  /** Test observer receives only source labels after real code consumes them. */
  redactionSourceObserved?: (source: string) => void;
}>;

export type DemoRunResult = Readonly<{
  exitCode: number;
  records: readonly DemoRecord[];
  journal: DemoJournal;
}>;
