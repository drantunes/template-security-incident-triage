import type { RetentionSchedulerConfig } from "../config/retention.js";
import type { OperationalStore } from "../db/operational-store.js";
import {
  sweepRetention,
  type RetentionSweepResult,
} from "../db/retention-operations.js";
import type { StructuredLogger } from "../logging.js";

type Timer = NodeJS.Timeout;

export type RetentionScheduler = Readonly<{ stop(): Promise<void> }>;

type RetentionSchedulerDependencies = Readonly<{
  now?: () => Date;
  runSweep?: (
    store: OperationalStore,
    input: Readonly<{ now: Date; limit: number; tenantId: string }>,
  ) => Promise<RetentionSweepResult>;
  setInterval?: (callback: () => void, intervalMs: number) => Timer;
  clearInterval?: (timer: Timer) => void;
}>;

/** Starts one tenant-scoped sweep now, then serializes subsequent 24h passes. */
export async function startRetentionScheduler(
  store: OperationalStore,
  config: RetentionSchedulerConfig,
  logger: StructuredLogger,
  dependencies: RetentionSchedulerDependencies = {},
): Promise<RetentionScheduler | undefined> {
  if (!config.enabled) return undefined;
  const tenantId = config.tenantId;
  const limit = config.limit;
  if (!tenantId || limit == null)
    throw new Error("RETENTION_SCHEDULER_CONFIG_INVALID");

  const now = dependencies.now ?? (() => new Date());
  const runSweep = dependencies.runSweep ?? sweepRetention;
  const schedule =
    dependencies.setInterval ??
    ((callback, intervalMs) => setInterval(callback, intervalMs));
  const clear = dependencies.clearInterval ?? ((timer) => clearInterval(timer));
  let stopped = false;
  let inFlight: Promise<void> | undefined;

  const run = async (startup: boolean): Promise<void> => {
    if (stopped || inFlight) return inFlight;
    const active = runSweep(store, {
      now: now(),
      limit,
      tenantId,
    })
      .then((result) => {
        logger.write({
          event: "retention.sweep.completed",
          ...(result.dryRun
            ? { errorCode: "RETENTION_DRY_RUN_UNEXPECTED" }
            : {}),
        });
      })
      .catch((error: unknown) => {
        logger.write({
          event: "retention.sweep.failed",
          errorCode: "RETENTION_SWEEP_FAILED",
        });
        if (startup) throw error;
      })
      .finally(() => {
        inFlight = undefined;
      });
    inFlight = active;
    return active;
  };

  await run(true);
  const timer = schedule(() => {
    void run(false);
  }, config.intervalMs);
  timer.unref();
  return Object.freeze({
    stop: async () => {
      if (stopped) return;
      stopped = true;
      clear(timer);
      await inFlight;
    },
  });
}
