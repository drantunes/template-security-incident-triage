import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

import { SpanType, type TracingContext } from "@mastra/core/observability";
import { RequestContext } from "@mastra/core/request-context";
import type { ToolObserve } from "@mastra/core/tools";
import { createStep } from "@mastra/core/workflows";

import { createLibSqlOperationalStore } from "../../db/libsql-operational-store.js";
import type { OperationalStore } from "../../db/operational-store.js";
import { systemClock, type Clock } from "../../domain/clock.js";
import { DomainError } from "../../domain/errors.js";
import { uuidGenerator, type IdGenerator } from "../../domain/id-generator.js";
import {
  BranchResultSchema,
  EvidenceProviderInputSchema,
  EvidenceToolOutputSchema,
  InvestigationContextSchema,
  type EvidenceProviderInput,
  type EvidenceSourceV1,
} from "../../evidence/contracts.js";
import { persistEvidenceItems } from "../../evidence/persistence.js";
import {
  generateWithOneSchemaRetry,
  InvestigatorOutputSchema,
  type InvestigatorInvoker,
} from "../agents/investigator-output.js";
import { projectFactsForPrompt } from "../agents/prompt-safe-evidence.js";
import type { EvidenceReadTool } from "../tools/evidence-read-tool.js";

export type GatherDependencies<Source extends EvidenceSourceV1> = Readonly<{
  openStore?: () => OperationalStore;
  tool: EvidenceReadTool & Readonly<{ __source?: Source }>;
  investigator: InvestigatorInvoker;
  timeoutMs?: number;
  toolObserve?: ToolObserve;
  clock?: Clock;
  monotonicNow?: () => number;
  ids?: IdGenerator;
}>;

export function createGatherEvidenceStep<Source extends EvidenceSourceV1>(
  source: Source,
  dependencies: GatherDependencies<Source>,
) {
  const stepId = `gather-${source}-evidence` as const;
  return createStep({
    id: stepId,
    description: `Collects and persists ${source} evidence within a bounded read-only scope.`,
    inputSchema: InvestigationContextSchema,
    outputSchema: BranchResultSchema,
    execute: async ({ inputData, abortSignal, tracingContext }) => {
      const clock = dependencies.clock ?? systemClock;
      const monotonicNow =
        dependencies.monotonicNow ?? (() => performance.now());
      const startedAt = clock.now();
      const startedMonotonic = monotonicNow();
      const toolCallId = `tc_${createHash("sha256")
        .update(`${inputData.workflowRunId}:${source}`, "utf8")
        .digest("hex")}`;
      const request = {
        tenantId: inputData.tenantId,
        incidentId: inputData.incidentId,
        subjectId: inputData.subjectId,
        workflowRunId: inputData.workflowRunId,
        incidentKind: inputData.incidentKind,
        occurredAt: inputData.occurredAt,
        ...(inputData.sessionId ? { sessionId: inputData.sessionId } : {}),
        ...(inputData.deviceId ? { deviceId: inputData.deviceId } : {}),
        ...(inputData.ip ? { ip: inputData.ip } : {}),
      };
      const parsedRequest = EvidenceProviderInputSchema.parse(request);
      const executeTool = dependencies.tool.execute;
      if (!executeTool || dependencies.tool.id !== `${source}-read-tool`)
        throw new DomainError("CONFLICT");
      const toolOutput = EvidenceToolOutputSchema.parse(
        await executeTool(parsedRequest, {
          requestContext: trustedRequestContext(parsedRequest),
          abortSignal,
          observe:
            dependencies.toolObserve ??
            workflowToolObserve(tracingContext, {
              tenantId: inputData.tenantId,
              incidentId: inputData.incidentId,
              runId: inputData.workflowRunId,
              correlationId: inputData.correlationId,
              stepId,
              source,
              toolId: dependencies.tool.id,
            }),
          ...(tracingContext
            ? { tracing: tracingContext, tracingContext }
            : {}),
          agent: {
            agentId: `${source}-investigator`,
            toolCallId,
            messages: [],
            suspend: async () => undefined,
          },
        }),
      );
      if (toolOutput.result.status !== "success") {
        return failedBranch(toolOutput.result.error);
      }
      const successfulResult = toolOutput.result;
      if (
        new Set(successfulResult.facts.map((fact) => fact.semanticKey)).size !==
        successfulResult.facts.length
      ) {
        return failedBranch({
          code: "INVALID_RESPONSE",
          retryable: false,
          safeRef: `provider:${source}-investigator:duplicate-key`,
          attempt: 1,
        });
      }
      const promptFacts = projectFactsForPrompt(
        successfulResult.facts.map((fact) => ({
          semanticKey: fact.semanticKey,
          factType: fact.factType,
          value: fact.value,
          sensitivity: fact.sensitivity,
        })),
      );
      const agentResult = await generateWithOneSchemaRetry(
        (attempt) =>
          dependencies.investigator(
            {
              facts: promptFacts,
            },
            attempt,
            abortSignal,
          ),
        InvestigatorOutputSchema,
      ).catch((error: unknown) => ({ status: "operational" as const, error }));
      if (agentResult.status === "operational")
        return failedBranch(
          agentOperationalFailure(source, agentResult.error, abortSignal),
        );
      if (
        agentResult.status !== "success" ||
        !citesExactly(
          agentResult.status === "success"
            ? agentResult.output.citedFactTokens
            : [],
          promptFacts.map((fact) => fact.factToken),
        )
      ) {
        return failedBranch({
          code: "INVALID_RESPONSE",
          retryable: false,
          safeRef: `provider:${source}-investigator:attempt-2`,
          attempt: 2,
        });
      }
      const store = (dependencies.openStore ?? createLibSqlOperationalStore)();
      try {
        const evidence = await persistEvidenceItems(
          store,
          {
            context: inputData,
            source,
            provider: successfulResult.provider,
            facts: successfulResult.facts,
          },
          {
            ...(dependencies.clock ? { clock: dependencies.clock } : {}),
            ids: dependencies.ids ?? uuidGenerator,
          },
        );
        const finishedAt = clock.now();
        return BranchResultSchema.parse({
          source,
          status: evidence.some((item) => item.incomplete)
            ? "partial"
            : "success",
          evidenceIds: evidence.map((item) => item.evidenceId),
          startedAt,
          finishedAt,
          latencyMs: Math.max(0, Math.round(monotonicNow() - startedMonotonic)),
          stepId,
          toolCallIds: [toolCallId],
        });
      } finally {
        store.close();
      }

      function failedBranch(error: {
        code:
          | "NOT_FOUND"
          | "TIMEOUT"
          | "UNAVAILABLE"
          | "RATE_LIMITED"
          | "INVALID_RESPONSE"
          | "ABORTED";
        retryable: boolean;
        safeRef: string;
        attempt: number;
      }) {
        const finishedAt = clock.now();
        return BranchResultSchema.parse({
          source,
          status: "failed",
          evidenceIds: [],
          error,
          startedAt,
          finishedAt,
          latencyMs: Math.max(0, Math.round(monotonicNow() - startedMonotonic)),
          stepId,
          toolCallIds: [toolCallId],
        });
      }
    },
  });
}

function trustedRequestContext(request: EvidenceProviderInput) {
  const context = new RequestContext<EvidenceProviderInput>();
  context.set("tenantId", request.tenantId);
  context.set("incidentId", request.incidentId);
  context.set("subjectId", request.subjectId);
  context.set("workflowRunId", request.workflowRunId);
  context.set("incidentKind", request.incidentKind);
  context.set("occurredAt", request.occurredAt);
  if (request.sessionId) context.set("sessionId", request.sessionId);
  if (request.deviceId) context.set("deviceId", request.deviceId);
  if (request.ip) context.set("ip", request.ip);
  return context;
}

function workflowToolObserve(
  tracingContext: TracingContext | undefined,
  scope: {
    tenantId: string;
    incidentId: string;
    runId: string;
    correlationId: string;
    stepId: string;
    source: EvidenceSourceV1;
    toolId: string;
  },
): ToolObserve {
  return {
    span: async (name, fn, attributes) => {
      const span = tracingContext?.currentSpan?.createChildSpan({
        name,
        type: SpanType.TOOL_CALL,
        attributes: {
          toolType:
            typeof attributes?.toolType === "string"
              ? attributes.toolType
              : "function",
          ...(typeof attributes?.toolCallId === "string"
            ? { toolCallId: attributes.toolCallId }
            : {}),
          ...scope,
        },
      });
      if (!span) return fn();
      try {
        const output = await span.executeInContext(async () => fn());
        span.end({ attributes: { success: true } });
        return output;
      } catch (error) {
        span.error({
          error: error instanceof Error ? error : new Error("Tool failed"),
          endSpan: true,
        });
        throw error;
      }
    },
    log: () => undefined,
  };
}

function agentOperationalFailure(
  source: EvidenceSourceV1,
  error: unknown,
  signal?: AbortSignal,
) {
  const description =
    error instanceof Error
      ? `${error.name}:${error.message}`.toLowerCase()
      : "unknown";
  const code = signal?.aborted
    ? ("ABORTED" as const)
    : /timeout|timed out/u.test(description)
      ? ("TIMEOUT" as const)
      : /rate.?limit/u.test(description)
        ? ("RATE_LIMITED" as const)
        : ("UNAVAILABLE" as const);
  return {
    code,
    retryable: false,
    safeRef: `provider:${source}-investigator:operational-error`,
    attempt: 1,
  };
}

function citesExactly(
  cited: readonly string[],
  available: readonly string[],
): boolean {
  const sortedCited = [...new Set(cited)].sort();
  const sortedAvailable = [...new Set(available)].sort();
  return (
    sortedCited.length === cited.length &&
    sortedCited.length === sortedAvailable.length &&
    sortedCited.every((key, index) => key === sortedAvailable[index])
  );
}
