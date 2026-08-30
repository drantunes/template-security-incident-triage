import { createHash } from "node:crypto";

import {
  DEMO_EXIT,
  DemoCommandSchema,
  DemoModeSchema,
  DemoScenarioSchema,
  DemoErrorRecordSchema,
  exitForDemoError,
  type DemoMode,
  type DemoScenario,
} from "../src/demo/contracts.js";
import { cleanupDemo, inspectDemo, runMockDemo } from "../src/demo/runner.js";
import { preflightDemo } from "../src/demo/preflight.js";
import { demoId } from "../src/demo/fixtures.js";

type ErrorContext = Readonly<{
  demoRunId?: string;
  scenario?: DemoScenario;
  mode?: DemoMode;
}>;

let knownErrorContext: ErrorContext = {};

function errorRecord(code: string, context: ErrorContext = knownErrorContext) {
  return DemoErrorRecordSchema.parse({
    schemaVersion: 1,
    type: "error",
    demoRunId: context.demoRunId ?? null,
    scenario: context.scenario ?? null,
    mode: context.mode ?? null,
    state: "error",
    occurredAt: new Date().toISOString(),
    code,
  });
}

function usage(code = "DEMO_USAGE_INVALID"): never {
  process.stdout.write(`${JSON.stringify(errorRecord(code))}\n`);
  process.exit(DEMO_EXIT.usage);
}

const [rawCommand, ...raw] = process.argv.slice(2);
if (rawCommand === "--help" || rawCommand === "-h" || rawCommand === "help") {
  process.stderr.write(
    `Usage: npm run demo -- <run|inspect|cleanup|preflight> [flags]\n\nrun --scenario <privilege|country|device> --run-key <opaque> [--decision approve|reject|expire] [--mode mock]\ninspect --demo-run-id <id>\ncleanup --demo-run-id <id> --confirm-cleanup\npreflight --scenario <privilege|country|device> --mode <mock|staging> [--real --confirm]\n`,
  );
  process.exit(DEMO_EXIT.ok);
}
let command: "run" | "inspect" | "cleanup" | "preflight";
try {
  command = DemoCommandSchema.parse(rawCommand);
} catch {
  usage();
}
const options = new Map<string, string | true>();
const known = new Set([
  "--scenario",
  "--mode",
  "--run-key",
  "--decision",
  "--demo-run-id",
  "--confirm-cleanup",
  "--real",
  "--confirm",
  "--timeout-ms",
  "--root",
]);
const flags = new Set(["--confirm-cleanup", "--real", "--confirm"]);
for (let index = 0; index < raw.length; index += 1) {
  const key = raw[index];
  if (!key || !known.has(key) || options.has(key)) usage();
  if (flags.has(key)) {
    options.set(key, true);
    continue;
  }
  const value = raw[index + 1];
  if (value && !value.startsWith("--")) {
    options.set(key, value);
    index += 1;
  } else options.set(key, true);
}
const commandOptions: Record<typeof command, ReadonlySet<string>> = {
  run: new Set([
    "--scenario",
    "--mode",
    "--run-key",
    "--decision",
    "--real",
    "--confirm",
    "--timeout-ms",
    "--root",
  ]),
  inspect: new Set(["--demo-run-id", "--root"]),
  cleanup: new Set(["--demo-run-id", "--confirm-cleanup", "--root"]),
  preflight: new Set(["--scenario", "--mode", "--real", "--confirm"]),
};
if ([...options.keys()].some((key) => !commandOptions[command].has(key)))
  usage();
const output = (value: unknown) =>
  process.stdout.write(`${JSON.stringify(value)}\n`);
const scenario = options.get("--scenario");
function parseScenarioOrUsage(value: string | true | undefined) {
  if (typeof value !== "string") usage();
  try {
    return DemoScenarioSchema.parse(value);
  } catch {
    usage("DEMO_SCENARIO_INVALID");
  }
}
let mode: DemoMode;
try {
  mode = DemoModeSchema.parse(options.get("--mode") ?? "mock");
  knownErrorContext = { mode };
} catch {
  usage();
}
// Context is factual once both values parse, even if a later argument (such
// as timeout) is invalid. Keep invalid/missing scenario or run key as null;
// never manufacture an identifier from malformed input.
if (command === "run" && typeof scenario === "string") {
  try {
    const parsedScenario = DemoScenarioSchema.parse(scenario);
    const runKey = options.get("--run-key");
    if (typeof runKey === "string" && runKey.length >= 8)
      knownErrorContext = {
        demoRunId: demoId(
          "demo",
          `${parsedScenario}\0${createHash("sha256").update(runKey).digest("hex")}`,
        ),
        scenario: parsedScenario,
        mode,
      };
    else knownErrorContext = { scenario: parsedScenario, mode };
  } catch {
    // The subsequent command-specific parser emits the stable usage record.
  }
}
const timeout = options.get("--timeout-ms");
if (
  timeout !== undefined &&
  (typeof timeout !== "string" ||
    !/^\d+$/u.test(timeout) ||
    Number(timeout) < 1 ||
    Number(timeout) > 300_000)
)
  usage("DEMO_TIMEOUT_INVALID");

try {
  if (command === "preflight") {
    if (typeof scenario !== "string") usage();
    const parsedScenario = parseScenarioOrUsage(scenario);
    knownErrorContext = { scenario: parsedScenario, mode };
    const result = preflightDemo({
      mode,
      real: options.get("--real") === true,
      confirmed: options.get("--confirm") === true,
      scenario: parsedScenario,
    });
    output({
      schemaVersion: 1,
      type: "preflight",
      demoRunId: null,
      state: "preflight",
      occurredAt: new Date().toISOString(),
      scenario,
      ...result,
    });
    process.exit(result.ok ? DEMO_EXIT.ok : DEMO_EXIT.preflight);
  }
  if (command === "inspect") {
    const id = options.get("--demo-run-id");
    if (typeof id !== "string") usage();
    if (!/^demo_[a-f0-9]{24}$/u.test(id)) usage("DEMO_RUN_ID_INVALID");
    knownErrorContext = { demoRunId: id };
    const result = await inspectDemo(
      typeof options.get("--root") === "string"
        ? options.get("--root")
        : undefined,
      id,
    );
    if (!result) {
      output(errorRecord("DEMO_RUN_NOT_FOUND"));
      process.exit(exitForDemoError("DEMO_RUN_NOT_FOUND"));
    }
    output({
      schemaVersion: 1,
      type: "state",
      demoRunId: result.demoRunId,
      scenario: result.scenario,
      mode: result.mode,
      state: result.state,
      occurredAt: result.updatedAt,
    });
    process.exit(DEMO_EXIT.ok);
  }
  if (command === "cleanup") {
    const id = options.get("--demo-run-id");
    if (typeof id !== "string" || options.get("--confirm-cleanup") !== true)
      usage();
    if (!/^demo_[a-f0-9]{24}$/u.test(id)) usage("DEMO_RUN_ID_INVALID");
    knownErrorContext = { demoRunId: id };
    const existing = await inspectDemo(
      typeof options.get("--root") === "string"
        ? options.get("--root")
        : undefined,
      id,
    );
    if (existing)
      knownErrorContext = {
        demoRunId: id,
        scenario: existing.scenario,
        mode: existing.mode,
      };
    const result = await cleanupDemo(
      typeof options.get("--root") === "string"
        ? options.get("--root")
        : undefined,
      id,
    );
    output({
      schemaVersion: 1,
      type: "cleanup",
      demoRunId: result.demoRunId,
      scenario: result.scenario,
      mode: result.mode,
      state: result.state,
      occurredAt: result.updatedAt,
    });
    process.exit(DEMO_EXIT.ok);
  }
  if (command !== "run" || typeof scenario !== "string") usage();
  const parsedScenario = parseScenarioOrUsage(scenario);
  if (mode === "mock" && (options.get("--real") || options.get("--confirm")))
    usage("DEMO_MOCK_CONSENT_FLAGS_INVALID");
  if (mode !== "mock") {
    const result = preflightDemo({
      mode,
      real: options.get("--real") === true,
      confirmed: options.get("--confirm") === true,
      scenario: parsedScenario,
    });
    output({
      schemaVersion: 1,
      type: "preflight",
      demoRunId: null,
      state: "preflight",
      occurredAt: new Date().toISOString(),
      scenario: parsedScenario,
      ...result,
    });
    process.exit(result.ok ? DEMO_EXIT.preflight : DEMO_EXIT.preflight);
  }
  const runKey = options.get("--run-key");
  if (typeof runKey !== "string" || runKey.length < 8) usage();
  knownErrorContext = {
    demoRunId: demoId(
      "demo",
      `${parsedScenario}\0${createHash("sha256").update(runKey).digest("hex")}`,
    ),
    scenario: parsedScenario,
    mode,
  };
  const decision = options.get("--decision");
  if (
    decision !== undefined &&
    decision !== "approve" &&
    decision !== "reject" &&
    decision !== "expire"
  )
    usage();
  const interruption = new AbortController();
  const onSigint = () => interruption.abort();
  process.once("SIGINT", onSigint);
  const stdoutWrite = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    process.stderr.write(chunk);
    return true;
  }) as typeof process.stdout.write;
  let result;
  try {
    result = await runMockDemo({
      scenario: parsedScenario,
      runKey,
      ...(typeof options.get("--root") === "string"
        ? { root: options.get("--root") }
        : {}),
      ...(decision ? { decision } : {}),
      ...(typeof timeout === "string" ? { timeoutMs: Number(timeout) } : {}),
      signal: interruption.signal,
    });
  } finally {
    process.stdout.write = stdoutWrite;
    process.removeListener("SIGINT", onSigint);
  }
  for (const record of result.records) output(record);
  process.exit(result.exitCode);
} catch (error) {
  const code = error instanceof Error ? error.message : "DEMO_FAILED";
  output(errorRecord(code));
  process.exit(exitForError(code));
}

function exitForError(code: string): number {
  return exitForDemoError(code);
}
