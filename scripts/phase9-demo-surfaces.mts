import {
  DemoErrorRecordSchema,
  DEMO_EXIT,
  exitForDemoError,
} from "../src/demo/contracts.js";
import { inspectDemo } from "../src/demo/runner.js";
import { observeDemoSurfaces } from "../src/demo/surfaces.js";

const args = process.argv.slice(2);
const id = args[0] === "--demo-run-id" ? args[1] : undefined;
const root = args[2] === "--root" ? args[3] : undefined;

/**
 * `process.exit()` can discard a buffered pipe write. This is observable on
 * the minimum supported Node runtime when a surface observation exceeds the
 * pipe high-water mark. Await both the write callback and drain when needed,
 * then let Node exit naturally through `process.exitCode`.
 */
async function writeAndFlush(
  stream: NodeJS.WriteStream,
  value: string,
): Promise<void> {
  let resolveWrite: (() => void) | undefined;
  let rejectWrite: ((error: Error) => void) | undefined;
  const written = new Promise<void>((resolve, reject) => {
    resolveWrite = resolve;
    rejectWrite = reject;
  });
  let resolveDrain: (() => void) | undefined;
  const drained = new Promise<void>((resolve) => {
    resolveDrain = resolve;
  });
  const onError = (error: Error) => rejectWrite?.(error);
  const onDrain = () => resolveDrain?.();
  stream.once("error", onError);
  stream.once("drain", onDrain);
  const needsDrain = !stream.write(value, () => resolveWrite?.());
  if (!needsDrain) stream.removeListener("drain", onDrain);
  try {
    await written;
    if (needsDrain) await drained;
  } finally {
    stream.removeListener("error", onError);
    stream.removeListener("drain", onDrain);
  }
}

async function emit(value: unknown): Promise<void> {
  await writeAndFlush(process.stdout, `${JSON.stringify(value)}\n`);
}

async function finish(exitCode: number): Promise<void> {
  // stdout has already carried the record, but empty writes serialize the
  // completion after any buffered diagnostics on both standard streams.
  await writeAndFlush(process.stdout, "");
  await writeAndFlush(process.stderr, "");
  process.exitCode = exitCode;
}

async function main(): Promise<void> {
  if (
    !id ||
    !/^demo_[a-f0-9]{24}$/u.test(id) ||
    args.length !== (root ? 4 : 2)
  ) {
    await emit(
      DemoErrorRecordSchema.parse({
        schemaVersion: 1,
        type: "error",
        demoRunId: null,
        scenario: null,
        mode: null,
        state: "error",
        occurredAt: new Date().toISOString(),
        code: "DEMO_USAGE_INVALID",
      }),
    );
    await finish(DEMO_EXIT.usage);
    return;
  }

  let context:
    | Readonly<{ scenario: "privilege" | "country" | "device"; mode: "mock" }>
    | undefined;
  try {
    const journal = await inspectDemo(root, id);
    if (!journal) throw new Error("DEMO_RUN_NOT_FOUND");
    context = { scenario: journal.scenario, mode: journal.mode };
    await emit(await observeDemoSurfaces(journal, root));
    await finish(DEMO_EXIT.ok);
  } catch (error) {
    const candidate = error instanceof Error ? error.message : undefined;
    const code =
      candidate && /^DEMO_[A-Z0-9_]+$/u.test(candidate)
        ? candidate
        : "DEMO_SURFACE_OBSERVATION_FAILED";
    await emit(
      DemoErrorRecordSchema.parse({
        schemaVersion: 1,
        type: "error",
        demoRunId: id,
        scenario: context?.scenario ?? null,
        mode: context?.mode ?? null,
        state: "error",
        occurredAt: new Date().toISOString(),
        code,
      }),
    );
    await finish(exitForDemoError(code));
  }
}

await main();
