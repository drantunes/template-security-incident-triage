import { MastraServer } from "@mastra/hono";
import type { Mastra } from "@mastra/core/mastra";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";

import type { OperationalStore } from "./db/operational-store.js";
import type { Phase2Config } from "./env.js";
import { errorResponse } from "./http-errors.js";
import {
  defensiveHeadersMiddleware,
  requestContextMiddleware,
  type AppEnv,
} from "./http-context.js";
import {
  consoleLogger,
  requestLoggingMiddleware,
  type StructuredLogger,
} from "./logging.js";
import { registerWebhookRoutes } from "./webhooks/routes.js";
import { registerApprovalRoutes } from "./approval/routes.js";
import { MockDecisionAuthenticator } from "./approval/mock-decision-authenticator.js";
import {
  createWorkflowApprovalRunReconciler,
  type ApprovalWorkflow,
} from "./approval/workflow-resume-reconciler.js";
import { readPhase6Config, type Phase6Config } from "./env.js";

export async function createApp(
  input: Readonly<{
    config: Phase2Config;
    store: OperationalStore;
    logger?: StructuredLogger;
    createRequestId?: () => string;
    nowMs?: () => number;
    mastraInstance?: Mastra;
    phase6Config?: Phase6Config;
  }>,
): Promise<Hono<AppEnv>> {
  const logger = input.logger ?? consoleLogger;
  const app = new Hono<AppEnv>();

  app.use("*", requestContextMiddleware(input.createRequestId));
  app.use("*", defensiveHeadersMiddleware);
  app.use("*", requestLoggingMiddleware(logger));

  app.get("/health", (context) => context.json({ status: "ok" }));
  registerWebhookRoutes(app, {
    config: input.config,
    store: input.store,
    logger,
    ...(input.nowMs ? { nowMs: input.nowMs } : {}),
  });

  app.use(
    "/api/*",
    bodyLimit({
      maxSize: input.config.mastraMaxBodyBytes,
      onError: (context) =>
        errorResponse(context, "PAYLOAD_TOO_LARGE", 413, false, logger),
    }),
  );

  const appMastra =
    input.mastraInstance ?? (await import("./mastra/index.js")).mastra;
  const phase6Config = input.phase6Config ?? readPhase6Config();
  if (
    phase6Config.mockDecisionsEnabled &&
    phase6Config.mockDecisionSecret &&
    phase6Config.approvalResumeSecret
  ) {
    const approvalWorkflow = (appMastra.getWorkflow as (id: string) => unknown)(
      "incidentIngestionWorkflow",
    ) as ApprovalWorkflow;
    registerApprovalRoutes(app, {
      config: phase6Config,
      store: input.store,
      logger,
      authenticator: new MockDecisionAuthenticator({
        mode: phase6Config.mode,
        enabled: phase6Config.mockDecisionsEnabled,
        secret: phase6Config.mockDecisionSecret,
        ...(input.nowMs ? { nowMs: input.nowMs } : {}),
      }),
      reconcileApprovalRun:
        createWorkflowApprovalRunReconciler(approvalWorkflow),
    });
  }

  const server = new MastraServer({
    app,
    mastra: appMastra,
    bodyLimitOptions: {
      maxSize: input.config.mastraMaxBodyBytes,
      onError: () => ({
        code: "PAYLOAD_TOO_LARGE",
        message: "The request body is too large.",
        retryable: false,
      }),
    },
  });
  await server.init();

  app.notFound((context) =>
    context.json(
      {
        code: "NOT_FOUND",
        message: "The requested resource was not found.",
        requestId: context.get("requestId"),
        retryable: false,
      },
      404,
    ),
  );
  app.onError((_, context) => {
    logger.write({
      event: "http.request.rejected",
      requestId: context.get("requestId"),
      correlationId: context.get("correlationId"),
      errorCode: "INTERNAL_ERROR",
      status: 500,
    });
    return context.json(
      {
        code: "INTERNAL_ERROR",
        message: "An internal error occurred.",
        requestId: context.get("requestId"),
        retryable: false,
      },
      500,
    );
  });

  return app;
}
