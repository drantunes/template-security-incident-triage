import { createStep } from "@mastra/core/workflows";

import {
  ContainmentExecutionResultSchema,
  Phase6ResultSchema,
} from "../../approval/phase6-contracts.js";
import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import type { Clock } from "../../domain/clock.js";
import type { IdGenerator } from "../../domain/id-generator.js";
import type { ContainmentExecutionResult } from "../../approval/phase6-contracts.js";
import { closeValidatedTerminalIncident } from "../../containment/terminal-readiness.js";

export function createFinalizeIncidentStep(
  dependencies: Readonly<{
    openStore?: () => OperationalStore;
    clock?: Clock;
    ids?: IdGenerator;
  }> = {},
) {
  return createStep({
    id: "finalize-incident",
    description:
      "Closes rejected or fully contained incidents and preserves failed/partial state.",
    inputSchema: ContainmentExecutionResultSchema,
    outputSchema: Phase6ResultSchema,
    execute: async ({ inputData }) => {
      if (
        inputData.status === "manual-review" ||
        inputData.status === "blocked"
      )
        return inputData;
      if (inputData.status === "containment-failed") {
        return {
          status: "failed" as const,
          incidentId: inputData.plan.incidentId,
          approvalId: inputData.authoritative.approvalId,
          partial: inputData.partial,
          outcomes: inputData.outcomes,
        };
      }
      if (inputData.status === "expired") {
        const store = (
          dependencies.openStore ?? createLibSqlOperationalStore
        )();
        try {
          // Expiry resumes the same durable workflow through the Phase 6
          // receipt. Keep its operational marker aligned with the completed
          // Mastra run just as approved/rejected terminal paths do.
          await store.execute({
            sql: `UPDATE workflow_runs SET status = 'completed', finished_at = ?
              WHERE run_id = ? AND incident_id = ? AND status = 'running'`,
            args: [
              dependencies.clock?.now() ?? new Date().toISOString(),
              inputData.workflowRunId,
              inputData.plan.incidentId,
            ],
          });
        } finally {
          store.close();
        }
        return {
          status: "expired" as const,
          incidentId: inputData.plan.incidentId,
          approvalId: inputData.authoritative.approvalId,
        };
      }
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        await closeValidatedTerminalIncident(
          store,
          {
            ...inputData,
            requestCorrelationId: inputData.correlationId,
            terminalCorrelationId: inputData.correlationId,
          },
          {
            ...(dependencies.clock ? { clock: dependencies.clock } : {}),
            ...(dependencies.ids ? { ids: dependencies.ids } : {}),
          },
        );
        // LibSQL is the operational source queried by the dashboard and the
        // demo verifier.  A completed Mastra run must not leave its durable
        // workflow marker at `running`, otherwise a restart can misclassify a
        // terminal incident as recoverable work.
        await store.execute({
          sql: `UPDATE workflow_runs SET status = 'completed', finished_at = ?
            WHERE run_id = ? AND incident_id = ? AND status = 'running'`,
          args: [
            dependencies.clock?.now() ?? new Date().toISOString(),
            inputData.workflowRunId,
            inputData.plan.incidentId,
          ],
        });
        return finalResult(inputData);
      } finally {
        store.close();
      }
    },
  });
}

type FinalizableInput = Extract<
  ContainmentExecutionResult,
  { status: "rejected" | "containment-succeeded" }
>;

function finalResult(input: FinalizableInput) {
  return input.status === "rejected"
    ? {
        status: "rejected" as const,
        incidentId: input.plan.incidentId,
        approvalId: input.authoritative.approvalId,
      }
    : {
        status: "contained" as const,
        incidentId: input.plan.incidentId,
        approvalId: input.authoritative.approvalId,
        outcomes: input.outcomes,
      };
}
