import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";

const baselineInputSchema = z.object({
  message: z.string().min(1),
});

const baselineOutputSchema = z.object({
  message: z.string(),
  status: z.literal("ready"),
});

const baselineStep = createStep({
  id: "baseline-check",
  description:
    "Returns a deterministic baseline status without external effects.",
  inputSchema: baselineInputSchema,
  outputSchema: baselineOutputSchema,
  execute: async ({ inputData }) => ({
    message: inputData.message,
    status: "ready" as const,
  }),
});

export const baselineWorkflow = createWorkflow({
  id: "baseline-workflow",
  description: "A deterministic placeholder workflow for Studio discovery.",
  inputSchema: baselineInputSchema,
  outputSchema: baselineOutputSchema,
})
  .then(baselineStep)
  .commit();
