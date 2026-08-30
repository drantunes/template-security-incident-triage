import type { DemoJournal, DemoRecord, DemoScenario } from "./contracts.js";

export type RunOptions = Readonly<{
  scenario: DemoScenario;
  runKey: string;
  root?: string;
  decision?: "approve" | "reject" | "expire";
  timeoutMs?: number;
  signal?: AbortSignal;
}>;

export type DemoRunResult = Readonly<{
  exitCode: number;
  records: readonly DemoRecord[];
  journal: DemoJournal;
}>;
