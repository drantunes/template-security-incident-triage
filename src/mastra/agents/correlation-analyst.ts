import { Agent } from "@mastra/core/agent";
import { z } from "zod";

import {
  EvidenceSourceV1Schema,
  MAX_CORRELATED_EVIDENCE_ITEMS,
  MAX_PAIRWISE_CONTRADICTIONS,
  type EvidenceSourceV1,
} from "../../evidence/contracts.js";
import { UNTRUSTED_DATA_INSTRUCTIONS } from "./investigator-output.js";
import { PromptSafeFactSchema } from "./prompt-safe-evidence.js";

export function createCorrelationAnalyst(model: string) {
  return new Agent({
    id: "correlation-analyst",
    name: "Correlation Analyst",
    description:
      "Validates a bounded summary of deterministic persisted-evidence correlation.",
    instructions: `${UNTRUSTED_DATA_INSTRUCTIONS}
You receive only prompt-safe tokens and numeric metadata derived from integrity-verified evidence.
Validate the deterministic counts. Never classify severity, summarize, plan, or propose actions.`,
    model,
    maxRetries: 0,
    tools: {},
    defaultOptions: {
      maxSteps: 1,
      maxProcessorRetries: 0,
      modelSettings: {
        temperature: 0,
        timeout: { totalMs: 3_000, stepMs: 1_500 },
      },
    },
  });
}

export const correlationAnalyst = createCorrelationAnalyst(
  process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
);

export const CorrelationAnalystOutputSchema = z
  .object({
    schemaVersion: z.literal(1),
    evidenceCount: z.number().int().min(0).max(MAX_CORRELATED_EVIDENCE_ITEMS),
    relationCount: z
      .number()
      .int()
      .min(0)
      .max(MAX_CORRELATED_EVIDENCE_ITEMS - 1),
    contradictionCount: z
      .number()
      .int()
      .min(0)
      .max(MAX_PAIRWISE_CONTRADICTIONS),
    missingDataCount: z
      .number()
      .int()
      .min(0)
      .max(MAX_CORRELATED_EVIDENCE_ITEMS),
    incompleteEvidenceCount: z
      .number()
      .int()
      .min(0)
      .max(MAX_CORRELATED_EVIDENCE_ITEMS),
  })
  .strict();

export type CorrelationAnalystOutput = z.infer<
  typeof CorrelationAnalystOutputSchema
>;

export type CorrelationAnalystInvocation = Readonly<{
  promptSafeEvidence: readonly Readonly<{
    position: number;
    source: EvidenceSourceV1;
    elapsedMs: number;
    factToken: string;
    factTypeToken: string;
    valueToken: string;
    valueType: "string" | "number" | "boolean" | "null";
    sensitivity: "public" | "internal" | "confidential" | "restricted";
    incomplete: boolean;
  }>[];
  candidate: CorrelationAnalystOutput;
}>;

export type CorrelationAnalystInvoker = (
  input: CorrelationAnalystInvocation,
  attempt: 1 | 2,
  signal?: AbortSignal,
) => Promise<unknown>;

export function correlationAnalystPrompt(
  input: CorrelationAnalystInvocation,
): string {
  const promptSafeEvidence = z
    .array(
      z
        .object({
          position: z.number().int().min(1).max(MAX_CORRELATED_EVIDENCE_ITEMS),
          source: EvidenceSourceV1Schema,
          elapsedMs: z.number().finite().nonnegative(),
          ...PromptSafeFactSchema.shape,
          incomplete: z.boolean(),
        })
        .strict(),
    )
    .max(MAX_CORRELATED_EVIDENCE_ITEMS)
    .parse(input.promptSafeEvidence);
  const candidate = CorrelationAnalystOutputSchema.parse(input.candidate);
  return `Validate this bounded deterministic correlation summary using only the prompt-safe tokens and numeric metadata.
The complete evidence IDs, relations, contradictions, and gaps remain server-side and are not model output.
Return the candidate exactly when its counts agree with the quoted projection.
<prompt-safe-evidence>${JSON.stringify(promptSafeEvidence)}</prompt-safe-evidence>
<bounded-candidate>${JSON.stringify(candidate)}</bounded-candidate>`;
}

export const invokeCorrelationAnalyst: CorrelationAnalystInvoker = async (
  input,
  _attempt,
  signal,
) =>
  (
    await correlationAnalyst.generate(correlationAnalystPrompt(input), {
      structuredOutput: { schema: CorrelationAnalystOutputSchema },
      toolChoice: "none",
      maxSteps: 1,
      ...(signal ? { abortSignal: signal } : {}),
    })
  ).object;
