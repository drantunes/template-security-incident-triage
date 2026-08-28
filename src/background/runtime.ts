import { serve } from "@hono/node-server";
import type { Mastra } from "@mastra/core/mastra";

import { createLibSqlOperationalStore } from "../db/libsql-operational-store.js";
import { migrateOperationalStore } from "../db/migrate.js";
import type { OperationalStore } from "../db/operational-store.js";
import {
  readPhase2Config,
  readPhase6Config,
  type Phase2Config,
  type Phase6Config,
} from "../env.js";
import { consoleLogger, type StructuredLogger } from "../logging.js";
import { createApp } from "../server.js";
import { MockIncidentProvider } from "../providers/mock-incident-provider.js";
import { OutboxDispatcher } from "./outbox-dispatcher.js";
import {
  startWorkflowWorker,
  type IngestionWorkflow,
} from "./workflow-worker.js";
import { Phase6RecoveryDispatcher } from "./phase6-recovery-dispatcher.js";
import {
  createWorkflowApprovalRunReconciler,
  type ApprovalWorkflow,
} from "../approval/workflow-resume-reconciler.js";

export type ServerRuntime = Readonly<{
  port: number;
  stop(): Promise<void>;
}>;

type BoundServer = Readonly<{ port: number; close(): Promise<void> }>;
type BindServer = (
  fetch: (request: Request) => Response | Promise<Response>,
  port: number,
) => Promise<BoundServer>;

export async function startServerRuntime(
  overrides: Readonly<{
    config?: Phase2Config;
    store?: OperationalStore;
    logger?: StructuredLogger;
    port?: number;
    mastraInstance?: Mastra;
    bindServer?: BindServer;
    phase6Config?: Phase6Config;
  }> = {},
): Promise<ServerRuntime> {
  const config = overrides.config ?? readPhase2Config();
  const store = overrides.store ?? createLibSqlOperationalStore();
  const logger = overrides.logger ?? consoleLogger;
  const runtimeMastra =
    overrides.mastraInstance ?? (await import("../mastra/index.js")).mastra;
  let unsubscribe: (() => Promise<void>) | undefined;
  let timer: NodeJS.Timeout | undefined;
  let server: BoundServer | undefined;
  let iteration: Promise<unknown> | undefined;
  let stopped = false;
  try {
    await migrateOperationalStore(store);
    const phase6Config = overrides.phase6Config ?? readPhase6Config();
    const app = await createApp({
      config,
      store,
      logger,
      mastraInstance: runtimeMastra,
      phase6Config,
    });
    await runtimeMastra.startWorkers();
    unsubscribe = await startWorkflowWorker({
      pubsub: runtimeMastra.pubsub,
      workflow: (runtimeMastra.getWorkflow as (name: string) => unknown)(
        "incidentIngestionWorkflow",
      ) as IngestionWorkflow,
      store,
      logger,
      maxAttempts: config.outbox.maxAttempts,
    });
    const dispatcher = new OutboxDispatcher(
      store,
      runtimeMastra.pubsub,
      config.outbox,
      logger,
    );
    const approvalWorkflow = (
      runtimeMastra.getWorkflow as (id: string) => unknown
    )("incidentIngestionWorkflow") as ApprovalWorkflow;
    const recovery = new Phase6RecoveryDispatcher({
      store,
      provider: new MockIncidentProvider({ store }),
      containmentState: {
        sessions: new Map(),
        roles: new Map(),
        devices: new Map(),
        reauthentication: new Map(),
        calls: new Map(),
      },
      mode: phase6Config.mode,
      actionTimeoutMs: phase6Config.actionTimeoutMs,
      rateLimit: phase6Config.rateLimit,
      reconcileApprovalRun:
        createWorkflowApprovalRunReconciler(approvalWorkflow),
    });
    await dispatcher.reconcile();
    timer = setInterval(() => {
      if (iteration) return;
      iteration = dispatcher
        .reconcile()
        .then(() => dispatcher.runOnce())
        .then(() => recovery.runOnce())
        .catch(() => {
          logger.write({
            event: "outbox.iteration.failed",
            errorCode: "OUTBOX_ITERATION_FAILED",
          });
        })
        .finally(() => {
          iteration = undefined;
        });
    }, config.outbox.pollIntervalMs);
    timer.unref();
    const requestedPort = overrides.port ?? config.port;
    server = await (overrides.bindServer ?? bindHttpServer)(
      app.fetch,
      requestedPort,
    );
    const port = server.port;
    return Object.freeze({
      port,
      stop: async () => {
        if (stopped) return;
        stopped = true;
        if (timer) clearInterval(timer);
        let shutdownError: unknown;
        const attempt = async (operation: () => void | Promise<void>) => {
          try {
            await operation();
          } catch (error) {
            shutdownError ??= error;
          }
        };
        if (server) await attempt(() => server!.close());
        await attempt(() =>
          Promise.race([
            iteration ?? Promise.resolve(),
            new Promise<void>((resolve) => setTimeout(resolve, 2_000)),
          ]).then(() => undefined),
        );
        await attempt(async () => unsubscribe?.());
        await attempt(() => runtimeMastra.pubsub.flush());
        await attempt(() => store.close());
        await attempt(() => runtimeMastra.shutdown());
        if (shutdownError) throw shutdownError;
      },
    });
  } catch (error) {
    if (timer) clearInterval(timer);
    await unsubscribe?.();
    await server?.close();
    store.close();
    await runtimeMastra.shutdown();
    throw error;
  }
}

const bindHttpServer: BindServer = async (fetch, port) => {
  const server = serve({ fetch, port });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  return {
    port: typeof address === "object" && address ? address.port : port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};
