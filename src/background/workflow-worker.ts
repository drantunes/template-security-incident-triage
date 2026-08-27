import type { PubSub } from "@mastra/core/events";
import { z } from "zod";

import type { OperationalStore } from "../db/operational-store.js";
import {
  hasUnresolvedOutboxDeadLetter,
  persistOutboxDeadLetter,
} from "../db/outbox-operations.js";
import {
  hasWorkflowRun,
  INCIDENT_INGESTION_WORKFLOW_ID,
  type StartInvestigationInput,
} from "../db/workflow-run-operations.js";
import { persistStandaloneDeadLetter } from "../db/webhook-operations.js";
import type { StructuredLogger } from "../logging.js";
import { DomainEventSchema } from "../schemas/domain-event.js";
import { opaqueId } from "../schemas/common.js";

const workerEventSchema = DomainEventSchema.extend({
  type: z.literal("security.alert.received"),
  data: DomainEventSchema.shape.data.extend({
    payload: z.object({ alertId: opaqueId }).passthrough(),
  }),
});

type WorkflowRun = Readonly<{
  startAsync(input: {
    inputData: StartInvestigationInput;
  }): Promise<{ runId: string }>;
}>;

export interface IngestionWorkflow {
  createRun(options: {
    runId: string;
    resourceId: string;
  }): Promise<WorkflowRun>;
}

export async function startWorkflowWorker(
  input: Readonly<{
    pubsub: PubSub;
    workflow: IngestionWorkflow;
    store: OperationalStore;
    logger: StructuredLogger;
    maxAttempts: number;
  }>,
): Promise<() => Promise<void>> {
  const callback = async (
    delivered: Parameters<Parameters<PubSub["subscribe"]>[1]>[0],
    ack?: () => Promise<void>,
    nack?: () => Promise<void>,
  ) => {
    const parsed = workerEventSchema.safeParse({
      type: delivered.type,
      runId: delivered.runId,
      data: delivered.data,
    });
    if (!parsed.success) {
      await persistStandaloneDeadLetter(input.store, {
        eventType: String(delivered.type),
        eventRef: `transport:${delivered.id}`,
        errorCode: "EVENT_INVALID",
      });
      input.logger.write({
        event: "worker.dead_lettered",
        errorCode: "EVENT_INVALID",
      });
      await ack?.();
      return;
    }
    const event = parsed.data;
    if (await hasUnresolvedOutboxDeadLetter(input.store, event.data.eventId)) {
      input.logger.write({
        event: "worker.no_op",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: event.data.eventId,
        errorCode: "WORKFLOW_START_FAILED",
      });
      await ack?.();
      return;
    }
    if (await hasWorkflowRun(input.store, event.data.eventId)) {
      input.logger.write({
        event: "worker.no_op",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: event.data.eventId,
      });
      await ack?.();
      return;
    }
    try {
      const run = await input.workflow.createRun({
        runId: event.data.eventId,
        resourceId: event.data.incidentId,
      });
      const started = await run.startAsync({
        inputData: {
          eventId: event.data.eventId,
          incidentId: event.data.incidentId,
          tenantId: event.data.tenantId,
          alertId: event.data.payload.alertId,
          correlationId: event.data.correlationId,
        },
      });
      input.logger.write({
        event: "worker.started",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        workflowRunId: started.runId,
      });
      await ack?.();
    } catch {
      const attempt = delivered.deliveryAttempt ?? 1;
      if (attempt < input.maxAttempts && nack) {
        input.logger.write({
          event: "worker.retry",
          correlationId: event.data.correlationId,
          incidentId: event.data.incidentId,
          errorCode: "WORKFLOW_START_FAILED",
          attempt,
        });
        await nack();
        return;
      }
      const terminal = await persistOutboxDeadLetter(input.store, {
        outboxId: event.data.eventId,
        errorCode: "WORKFLOW_START_FAILED",
        attemptCount: attempt,
        createdAt: new Date().toISOString(),
      });
      if (terminal === "outbox_missing") {
        await persistStandaloneDeadLetter(input.store, {
          eventType: event.type,
          eventRef: `event:${event.data.eventId}`,
          errorCode: "WORKFLOW_START_FAILED",
          tenantId: event.data.tenantId,
          incidentId: event.data.incidentId,
        });
      }
      input.logger.write({
        event:
          terminal === "workflow_run_exists"
            ? "worker.no_op"
            : "worker.dead_lettered",
        correlationId: event.data.correlationId,
        incidentId: event.data.incidentId,
        errorCode: "WORKFLOW_START_FAILED",
        attempt,
      });
      await ack?.();
    }
  };
  await input.pubsub.subscribe("security.alert.received", callback, {
    group: "security-workflow-starters",
  });
  return () => input.pubsub.unsubscribe("security.alert.received", callback);
}

export { INCIDENT_INGESTION_WORKFLOW_ID };
