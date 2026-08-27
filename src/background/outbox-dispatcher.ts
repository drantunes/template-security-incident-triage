import type { PubSub } from "@mastra/core/events";

import {
  claimOutboxBatch,
  markOutboxPublished,
  recordOutboxFailure,
  reconcilePublishedAlertsWithoutRun,
} from "../db/outbox-operations.js";
import type { OperationalStore } from "../db/operational-store.js";
import { DomainError } from "../domain/errors.js";
import type { StructuredLogger } from "../logging.js";

export type DispatcherOptions = Readonly<{
  batchSize: number;
  leaseMs: number;
  maxAttempts: number;
  backoffBaseMs: number;
  backoffCapMs: number;
  recoveryGraceMs: number;
}>;

export class OutboxDispatcher {
  constructor(
    private readonly store: OperationalStore,
    private readonly pubsub: PubSub,
    private readonly options: DispatcherOptions,
    private readonly logger: StructuredLogger,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async reconcile(): Promise<number> {
    const now = this.now();
    return reconcilePublishedAlertsWithoutRun(this.store, {
      now: now.toISOString(),
      olderThan: new Date(
        now.getTime() - this.options.recoveryGraceMs,
      ).toISOString(),
    });
  }

  async runOnce(): Promise<number> {
    const now = this.now();
    const leaseUntil = new Date(
      now.getTime() + this.options.leaseMs,
    ).toISOString();
    let claimed;
    try {
      claimed = await claimOutboxBatch(this.store, {
        now: now.toISOString(),
        leaseUntil,
        limit: this.options.batchSize,
      });
    } catch (error) {
      if (error instanceof DomainError && error.code === "VALIDATION_FAILED") {
        this.logger.write({
          event: "outbox.claim.failed",
          errorCode: "EVENT_INVALID",
        });
      }
      throw error;
    }
    for (const item of claimed) {
      if (!item.valid) {
        const outcome = await recordOutboxFailure(this.store, {
          id: item.id,
          leaseToken: item.leaseToken,
          now: this.now().toISOString(),
          errorCode: "EVENT_INVALID",
          maxAttempts: this.options.maxAttempts,
          backoffBaseMs: this.options.backoffBaseMs,
          backoffCapMs: this.options.backoffCapMs,
        });
        this.logger.write({
          event: `outbox.${outcome}`,
          errorCode: "EVENT_INVALID",
          attempt:
            outcome === "workflow_run_exists"
              ? item.attemptCount
              : item.attemptCount + 1,
        });
        continue;
      }
      try {
        await this.pubsub.publish(item.event.type, item.event);
      } catch {
        const outcome = await recordOutboxFailure(this.store, {
          id: item.event.data.eventId,
          leaseToken: item.leaseToken,
          now: this.now().toISOString(),
          errorCode: "PUBSUB_UNAVAILABLE",
          maxAttempts: this.options.maxAttempts,
          backoffBaseMs: this.options.backoffBaseMs,
          backoffCapMs: this.options.backoffCapMs,
        });
        this.logger.write({
          event: `outbox.${outcome}`,
          correlationId: item.event.data.correlationId,
          incidentId: item.event.data.incidentId,
          errorCode: "PUBSUB_UNAVAILABLE",
          attempt:
            outcome === "workflow_run_exists"
              ? item.attemptCount
              : item.attemptCount + 1,
        });
        continue;
      }
      try {
        const published = await markOutboxPublished(this.store, {
          id: item.event.data.eventId,
          leaseToken: item.leaseToken,
          publishedAt: this.now().toISOString(),
        });
        this.logger.write({
          event: published ? "outbox.published" : "outbox.fence_lost",
          correlationId: item.event.data.correlationId,
          incidentId: item.event.data.incidentId,
          attempt: item.attemptCount + 1,
        });
      } catch {
        this.logger.write({
          event: "outbox.mark_failed",
          correlationId: item.event.data.correlationId,
          incidentId: item.event.data.incidentId,
          errorCode: "STORAGE_UNAVAILABLE",
          attempt: item.attemptCount + 1,
        });
      }
    }
    return claimed.length;
  }
}
