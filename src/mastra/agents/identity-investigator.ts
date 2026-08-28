import { Agent } from "@mastra/core/agent";

import { identityReadTool } from "../tools/identity-read-tool.js";
import {
  InvestigatorOutputSchema,
  investigatorPrompt,
  UNTRUSTED_DATA_INSTRUCTIONS,
  type InvestigatorInvoker,
} from "./investigator-output.js";

export const identityInvestigator = new Agent({
  id: "identity-investigator",
  name: "Identity Investigator",
  description: "Cites identity facts for one trusted investigation scope.",
  instructions: `${UNTRUSTED_DATA_INSTRUCTIONS}\nUse only identity-read-tool.`,
  model: process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
  maxRetries: 0,
  tools: { identityReadTool },
  defaultOptions: {
    maxSteps: 3,
    maxProcessorRetries: 0,
    modelSettings: {
      temperature: 0,
      timeout: { totalMs: 3_000, stepMs: 1_500 },
    },
  },
});

export const invokeIdentityInvestigator: InvestigatorInvoker = async (
  input,
  _attempt,
  signal,
) =>
  (
    await identityInvestigator.generate(investigatorPrompt(input), {
      structuredOutput: { schema: InvestigatorOutputSchema },
      toolChoice: "none",
      maxSteps: 1,
      ...(signal ? { abortSignal: signal } : {}),
    })
  ).object;
