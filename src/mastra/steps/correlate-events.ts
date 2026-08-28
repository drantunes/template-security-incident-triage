import { createStep } from "@mastra/core/workflows";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import type { Clock } from "../../domain/clock.js";
import { DomainError } from "../../domain/errors.js";
import { canonicalJson } from "../../evidence/canonicalize.js";
import { appendCorrelationTimeline } from "../../evidence/correlation-timeline.js";
import {
  CorrelationSchema,
  ParallelEvidenceSchema,
  type BranchResult,
} from "../../evidence/contracts.js";
import { readVerifiedEvidence } from "../../evidence/persistence.js";
import type { Evidence } from "../../schemas/evidence.js";
import {
  CorrelationAnalystOutputSchema,
  invokeCorrelationAnalyst,
  type CorrelationAnalystInvoker,
} from "../agents/correlation-analyst.js";
import { generateWithOneSchemaRetry } from "../agents/investigator-output.js";
import { projectFactsForPrompt } from "../agents/prompt-safe-evidence.js";
import { loadInvestigationContext } from "./load-investigation-context.js";

export const CORRELATION_WINDOW_MS = 15 * 60 * 1_000;

export function createCorrelateEventsStep(
  dependencies: Readonly<{
    openStore?: () => OperationalStore;
    clock?: Clock;
    analyst?: CorrelationAnalystInvoker;
  }> = {},
) {
  return createStep({
    id: "correlate-events",
    description:
      "Executes the correlation analyst over integrity-verified persisted evidence IDs.",
    inputSchema: ParallelEvidenceSchema,
    outputSchema: CorrelationSchema,
    execute: async ({ inputData, getInitData, abortSignal }) => {
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        const initial = getInitData<{
          eventId: string;
          incidentId: string;
          tenantId: string;
          alertId: string;
          correlationId: string;
        }>();
        const context = await loadInvestigationContext(store, {
          ...initial,
          runId: initial.eventId,
          duplicate: false,
        });
        const branches = orderedBranches(inputData);
        const expectedSourceById = new Map<string, BranchResult["source"]>();
        for (const branch of branches) {
          if (branch.status === "failed" && branch.evidenceIds.length > 0)
            throw new DomainError("CONFLICT");
          for (const evidenceId of branch.evidenceIds) {
            if (expectedSourceById.has(evidenceId))
              throw new DomainError("CONFLICT");
            expectedSourceById.set(evidenceId, branch.source);
          }
        }
        const evidence = await readVerifiedEvidence(
          store,
          context,
          branches.flatMap((branch) => branch.evidenceIds),
        );
        for (const item of evidence) {
          if (expectedSourceById.get(item.evidenceId) !== item.source)
            throw new DomainError("CONFLICT");
        }
        for (const branch of branches) {
          const hasIncomplete = evidence.some(
            (item) =>
              expectedSourceById.get(item.evidenceId) === branch.source &&
              item.incomplete,
          );
          if (
            (branch.status === "partial") !== hasIncomplete ||
            (branch.status === "success" && hasIncomplete)
          ) {
            throw new DomainError("CONFLICT");
          }
        }
        const ordered = [...evidence].sort(
          (left, right) =>
            left.observedAt.localeCompare(right.observedAt) ||
            left.evidenceId.localeCompare(right.evidenceId),
        );
        const relations = findWindowRelations(ordered);
        const contradictions = findContradictions(ordered);
        const missingData = findMissingData(branches, ordered);
        const result = CorrelationSchema.parse({
          context,
          branches,
          orderedEvents: ordered.map((item) => ({
            evidenceId: item.evidenceId,
            observedAt: item.observedAt,
          })),
          relations,
          contradictions,
          missingData,
        });
        const promptFacts = projectFactsForPrompt(
          ordered.map((item) => ({
            semanticKey: String(item.fact.semanticKey ?? "missing"),
            factType: String(item.fact.factType),
            value:
              typeof item.fact.value === "string" ||
              typeof item.fact.value === "number" ||
              typeof item.fact.value === "boolean"
                ? item.fact.value
                : null,
            sensitivity: item.sensitivity,
          })),
        );
        const firstObservedAt = ordered[0]
          ? Date.parse(ordered[0].observedAt)
          : 0;
        const candidate = CorrelationAnalystOutputSchema.parse({
          schemaVersion: 1,
          evidenceCount: result.orderedEvents.length,
          relationCount: result.relations.length,
          contradictionCount: result.contradictions.length,
          missingDataCount: result.missingData.length,
          incompleteEvidenceCount: ordered.filter((item) => item.incomplete)
            .length,
        });
        const analysis = await generateWithOneSchemaRetry(
          (attempt) =>
            (dependencies.analyst ?? invokeCorrelationAnalyst)(
              {
                promptSafeEvidence: promptFacts.map((fact, index) => ({
                  position: index + 1,
                  source: ordered[index]!.source as
                    "identity" | "endpoint" | "cloud",
                  elapsedMs:
                    Date.parse(ordered[index]!.observedAt) - firstObservedAt,
                  ...fact,
                  incomplete: ordered[index]!.incomplete,
                })),
                candidate,
              },
              attempt,
              abortSignal,
            ),
          CorrelationAnalystOutputSchema,
        );
        if (
          analysis.status !== "success" ||
          canonicalJson(analysis.output) !== canonicalJson(candidate)
        ) {
          throw new DomainError("VALIDATION_FAILED");
        }
        await appendCorrelationTimeline(store, result, dependencies);
        return result;
      } finally {
        store.close();
      }
    },
  });
}

function orderedBranches(
  input: typeof ParallelEvidenceSchema._output,
): BranchResult[] {
  return [
    input["gather-identity-evidence"],
    input["gather-endpoint-evidence"],
    input["gather-cloud-evidence"],
  ];
}

export function findWindowRelations(evidence: readonly Evidence[]) {
  const relations: Array<{
    fromEvidenceId: string;
    toEvidenceId: string;
    type: "same-subject-within-15m-v1";
  }> = [];
  for (let index = 1; index < evidence.length; index += 1) {
    const previous = evidence[index - 1]!;
    const current = evidence[index]!;
    const delta =
      Date.parse(current.observedAt) - Date.parse(previous.observedAt);
    if (delta >= 0 && delta <= CORRELATION_WINDOW_MS) {
      relations.push({
        fromEvidenceId: previous.evidenceId,
        toEvidenceId: current.evidenceId,
        type: "same-subject-within-15m-v1",
      });
    }
  }
  return relations;
}

export function findContradictions(evidence: readonly Evidence[]) {
  const contradictions: Array<{
    leftEvidenceId: string;
    rightEvidenceId: string;
    reason: string;
  }> = [];
  for (let left = 0; left < evidence.length; left += 1) {
    for (let right = left + 1; right < evidence.length; right += 1) {
      const a = evidence[left]!;
      const b = evidence[right]!;
      if (
        a.fact.factType === b.fact.factType &&
        a.fact.value !== b.fact.value
      ) {
        contradictions.push({
          leftEvidenceId: a.evidenceId,
          rightEvidenceId: b.evidenceId,
          reason: `Conflicting values for ${String(a.fact.factType)}`,
        });
      }
    }
  }
  return contradictions;
}

function findMissingData(
  branches: readonly BranchResult[],
  evidence: readonly Evidence[],
) {
  return [
    ...branches
      .filter((branch) => branch.status === "failed")
      .map((branch) => ({
        source: branch.source,
        reason: branch.error?.code ?? "SOURCE_UNAVAILABLE",
      })),
    ...evidence
      .filter((item) => item.incomplete)
      .map((item) => ({
        source: item.source as "identity" | "endpoint" | "cloud",
        evidenceId: item.evidenceId,
        reason: item.error ?? "INCOMPLETE_EVIDENCE",
      })),
  ];
}
