import { bodyLimit } from "hono/body-limit";
import type { Context, Hono, MiddlewareHandler } from "hono";
import { ZodError } from "zod";

import { createIncidentFromAlertResult } from "../db/incident-operations.js";
import type { OperationalStore } from "../db/operational-store.js";
import { persistStandaloneDeadLetter } from "../db/webhook-operations.js";
import { DomainError } from "../domain/errors.js";
import type { Phase2Config } from "../env.js";
import { errorResponse } from "../http-errors.js";
import type { AppEnv } from "../http-context.js";
import type { StructuredLogger } from "../logging.js";
import { normalizeDemoAlert, normalizeWorkOsMock } from "./normalizers.js";
import { SignatureError, verifyWebhookSignature } from "./signature.js";

type WebhookRouteDependencies = Readonly<{
  config: Phase2Config;
  store: OperationalStore;
  logger: StructuredLogger;
  nowMs?: () => number;
}>;

class PayloadDecodeError extends Error {}

export function registerWebhookRoutes(
  app: Hono<AppEnv>,
  dependencies: WebhookRouteDependencies,
): void {
  if (!dependencies.config.webhooksEnabled) return;
  const mediaType = requireJsonContentType(dependencies.logger);
  const limit = bodyLimit({
    maxSize: dependencies.config.webhookMaxBodyBytes,
    onError: (context) =>
      errorResponse(
        context as never,
        "PAYLOAD_TOO_LARGE",
        413,
        false,
        dependencies.logger,
      ),
  });
  app.post("/webhooks/alerts", mediaType, limit, async (context) => {
    return handleWebhook(context, dependencies, {
      signatureHeader: "X-Alert-Signature",
      secret: dependencies.config.alertWebhookSecret!,
      eventType: "demo.alert",
      normalize: (value, bytes) =>
        normalizeDemoAlert(
          value,
          bytes,
          dependencies.config.alertWebhookSources,
        ),
    });
  });
  app.post("/webhooks/workos", mediaType, limit, async (context) => {
    return handleWebhook(context, dependencies, {
      signatureHeader: "WorkOS-Signature",
      secret: dependencies.config.workosWebhookSecret!,
      eventType: "workos.mock",
      normalize: normalizeWorkOsMock,
    });
  });
}

async function handleWebhook(
  context: Context<AppEnv>,
  dependencies: WebhookRouteDependencies,
  route: Readonly<{
    signatureHeader: string;
    secret: string;
    eventType: string;
    normalize: (
      value: unknown,
      rawBody: Uint8Array,
    ) => ReturnType<typeof normalizeDemoAlert>;
  }>,
) {
  let outOfOrderEventRef: string | undefined;
  try {
    const rawBody = new Uint8Array(await context.req.arrayBuffer());
    verifyWebhookSignature({
      header: context.req.header(route.signatureHeader),
      secret: route.secret,
      rawBody,
      nowMs: dependencies.nowMs?.(),
    });
    const value = parseJsonStrictUtf8(rawBody);
    const normalized = route.normalize(value, rawBody);
    if (normalized.disposition === "dead_letter") {
      await persistStandaloneDeadLetter(dependencies.store, {
        eventType: route.eventType,
        eventRef: normalized.eventRef,
        errorCode: normalized.reasonCode,
      });
      return context.json(
        {
          accepted: false,
          disposition: "dead_lettered",
          reasonCode: normalized.reasonCode,
          requestId: context.get("requestId"),
          correlationId: context.get("correlationId"),
        },
        202,
      );
    }
    outOfOrderEventRef = normalized.alert.rawPayloadRef;
    const result = await createIncidentFromAlertResult(
      dependencies.store,
      normalized.alert,
      {
        correlationId: context.get("correlationId"),
        enforceAlertOrdering: true,
      },
    );
    context.set("incidentId", result.incident.incidentId);
    dependencies.logger.write({
      event: result.duplicate
        ? "webhook.ingest.duplicate"
        : "webhook.ingest.committed",
      requestId: context.get("requestId"),
      correlationId: context.get("correlationId"),
      incidentId: result.incident.incidentId,
    });
    return context.json(
      {
        accepted: true,
        duplicate: result.duplicate,
        incidentId: result.incident.incidentId,
        requestId: context.get("requestId"),
        correlationId: context.get("correlationId"),
      },
      202,
    );
  } catch (error) {
    if (error instanceof SignatureError) {
      return errorResponse(
        context,
        error.code,
        401,
        false,
        dependencies.logger,
      );
    }
    if (error instanceof ZodError || error instanceof PayloadDecodeError) {
      return errorResponse(
        context,
        "PAYLOAD_INVALID",
        422,
        false,
        dependencies.logger,
      );
    }
    if (
      error instanceof Error &&
      error.message === "ALERT_SOURCE_UNSUPPORTED"
    ) {
      return errorResponse(
        context,
        "PAYLOAD_INVALID",
        422,
        false,
        dependencies.logger,
      );
    }
    if (error instanceof DomainError) {
      if (error.code === "EVENT_OUT_OF_ORDER" && outOfOrderEventRef) {
        try {
          await persistStandaloneDeadLetter(dependencies.store, {
            eventType: route.eventType,
            eventRef: outOfOrderEventRef,
            errorCode: "EVENT_OUT_OF_ORDER",
          });
        } catch (persistenceError) {
          return persistenceError instanceof DomainError &&
            persistenceError.code === "STORAGE_UNAVAILABLE"
            ? errorResponse(
                context,
                "STORAGE_UNAVAILABLE",
                503,
                true,
                dependencies.logger,
              )
            : errorResponse(
                context,
                "INTERNAL_ERROR",
                500,
                false,
                dependencies.logger,
              );
        }
        return context.json(
          {
            accepted: false,
            disposition: "dead_lettered",
            reasonCode: "EVENT_OUT_OF_ORDER",
            requestId: context.get("requestId"),
            correlationId: context.get("correlationId"),
          },
          202,
        );
      }
      if (error.code === "CONFLICT") {
        return errorResponse(
          context,
          "ALERT_CONFLICT",
          409,
          false,
          dependencies.logger,
        );
      }
      if (error.code === "STORAGE_UNAVAILABLE") {
        return errorResponse(
          context,
          "STORAGE_UNAVAILABLE",
          503,
          true,
          dependencies.logger,
        );
      }
      if (error.code === "VALIDATION_FAILED") {
        return errorResponse(
          context,
          "PAYLOAD_INVALID",
          422,
          false,
          dependencies.logger,
        );
      }
    }
    return errorResponse(
      context,
      "INTERNAL_ERROR",
      500,
      false,
      dependencies.logger,
    );
  }
}

function requireJsonContentType(
  logger: StructuredLogger,
): MiddlewareHandler<AppEnv> {
  return async (context, next) => {
    const contentType = context.req.header("Content-Type");
    if (contentType?.toLowerCase() !== "application/json") {
      return errorResponse(
        context,
        "UNSUPPORTED_MEDIA_TYPE",
        415,
        false,
        logger,
      );
    }
    await next();
  };
}

function parseJsonStrictUtf8(rawBody: Uint8Array): unknown {
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(rawBody);
    return JSON.parse(decoded) as unknown;
  } catch {
    throw new PayloadDecodeError();
  }
}
