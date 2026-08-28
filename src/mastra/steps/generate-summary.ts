import { createStep } from "@mastra/core/workflows";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import { canonicalJson } from "../../evidence/canonicalize.js";
import {
  CorrelationSchema,
  type Correlation,
} from "../../evidence/contracts.js";
import {
  buildIncidentSummary,
  createSummaryCandidate,
  validateSummaryReferences,
} from "../../triage/claims.js";
import { loadDecisionContext } from "../../triage/decision-context.js";
import {
  ClassificationStepResultSchema,
  SummaryAnalysisCandidateSchema,
  SummaryStepResultSchema,
} from "../../triage/decision-contracts.js";
import { appendPhase5Timeline } from "../../triage/decision-timeline.js";
import { assertSeverityDecision } from "../../triage/decision-validation.js";
import { projectDecisionContext } from "../../triage/prompt-safe-decision.js";
import { generateWithOneSchemaRetry } from "../agents/investigator-output.js";
import { invokeResponsePlanner } from "../agents/response-planner.js";
import type { Phase5StepDependencies } from "./classify-severity.js";
import { RunbookRetrievedSchema } from "./retrieve-runbook.js";

export function createGenerateSummaryStep(
  dependencies: Phase5StepDependencies = {},
) {
  return createStep({
    id: "generate-summary",
    description:
      "Builds a redacted summary with code-validated evidence references.",
    inputSchema: ClassificationStepResultSchema,
    outputSchema: SummaryStepResultSchema,
    execute: async ({ inputData, getStepResult, abortSignal }) => {
      if (inputData.status !== "classified") return inputData;
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        const correlation = CorrelationSchema.parse(
          getStepResult<Correlation>("correlate-events"),
        );
        const retrieval = RunbookRetrievedSchema.parse(
          getStepResult<typeof RunbookRetrievedSchema._output>(
            "retrieve-runbook",
          ),
        );
        let context;
        try {
          context = await loadDecisionContext(
            store,
            retrieval,
            correlation,
            dependencies,
          );
          assertSeverityDecision(context, inputData.decision);
        } catch {
          return SummaryStepResultSchema.parse({
            status: "blocked",
            incidentId: inputData.decision.incidentId,
            reasonCodes: ["INTEGRITY_CHECK_FAILED"],
          });
        }
        const candidate = createSummaryCandidate(context);
        let generated;
        try {
          generated = await generateWithOneSchemaRetry(
            (attempt) =>
              (dependencies.planner ?? invokeResponsePlanner)(
                {
                  task: "summary",
                  projection: projectDecisionContext(context),
                  candidate,
                },
                attempt,
                abortSignal,
              ),
            SummaryAnalysisCandidateSchema,
          );
        } catch {
          const stopped = {
            status: "manual-review" as const,
            incidentId: inputData.decision.incidentId,
            reasonCodes: ["MODEL_UNAVAILABLE" as const],
          };
          await appendPhase5Timeline(
            store,
            context,
            "summary",
            "manual-review",
            {
              result: stopped.status,
              reasonCodes: stopped.reasonCodes.join(","),
            },
          );
          return stopped;
        }
        if (
          generated.status !== "success" ||
          canonicalJson(generated.output) !== canonicalJson(candidate)
        ) {
          const stopped = {
            status: "blocked" as const,
            incidentId: inputData.decision.incidentId,
            reasonCodes: [
              generated.status === "success"
                ? ("CLAIM_REJECTED" as const)
                : ("MODEL_SCHEMA_INVALID" as const),
            ],
          };
          await appendPhase5Timeline(store, context, "summary", "blocked", {
            result: stopped.status,
            reasonCodes: stopped.reasonCodes.join(","),
          });
          return stopped;
        }
        const summary = buildIncidentSummary(
          context,
          inputData.decision,
          generated.output,
        );
        validateSummaryReferences(summary, context, inputData.decision);
        await appendPhase5Timeline(store, context, "summary", "completed", {
          result: "summarized",
          factCount: summary.facts.length,
          hypothesisCount: summary.hypotheses.length,
        });
        return SummaryStepResultSchema.parse({
          status: "summarized",
          decision: inputData.decision,
          summary,
        });
      } finally {
        store.close();
      }
    },
  });
}
