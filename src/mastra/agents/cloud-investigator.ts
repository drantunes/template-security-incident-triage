import { Agent } from "@mastra/core/agent";

import { cloudReadTool } from "../tools/cloud-read-tool.js";
import {
  InvestigatorOutputSchema,
  investigatorPrompt,
  UNTRUSTED_DATA_INSTRUCTIONS,
  type InvestigatorInvoker,
} from "./investigator-output.js";

export const cloudInvestigator = new Agent({
  id: "cloud-investigator",
  name: "Cloud Investigator",
  description: "Cites cloud facts for one trusted investigation scope.",
  instructions: `${UNTRUSTED_DATA_INSTRUCTIONS}\nUse only cloud-read-tool.`,
  model: process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
  maxRetries: 0,
  tools: { cloudReadTool },
  defaultOptions: {
    maxSteps: 3,
    maxProcessorRetries: 0,
    modelSettings: {
      temperature: 0,
      timeout: { totalMs: 3_000, stepMs: 1_500 },
    },
  },
});

export const invokeCloudInvestigator: InvestigatorInvoker = async (
  input,
  _attempt,
  signal,
) =>
  (
    await cloudInvestigator.generate(investigatorPrompt(input), {
      structuredOutput: { schema: InvestigatorOutputSchema },
      toolChoice: "none",
      maxSteps: 1,
      ...(signal ? { abortSignal: signal } : {}),
    })
  ).object;
