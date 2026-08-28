import { Agent } from "@mastra/core/agent";

import { endpointReadTool } from "../tools/endpoint-read-tool.js";
import {
  InvestigatorOutputSchema,
  investigatorPrompt,
  UNTRUSTED_DATA_INSTRUCTIONS,
  type InvestigatorInvoker,
} from "./investigator-output.js";

export const endpointInvestigator = new Agent({
  id: "endpoint-investigator",
  name: "Endpoint Investigator",
  description: "Cites endpoint facts for one trusted investigation scope.",
  instructions: `${UNTRUSTED_DATA_INSTRUCTIONS}\nUse only endpoint-read-tool.`,
  model: process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
  maxRetries: 0,
  tools: { endpointReadTool },
  defaultOptions: {
    maxSteps: 3,
    maxProcessorRetries: 0,
    modelSettings: {
      temperature: 0,
      timeout: { totalMs: 3_000, stepMs: 1_500 },
    },
  },
});

export const invokeEndpointInvestigator: InvestigatorInvoker = async (
  input,
  _attempt,
  signal,
) =>
  (
    await endpointInvestigator.generate(investigatorPrompt(input), {
      structuredOutput: { schema: InvestigatorOutputSchema },
      toolChoice: "none",
      maxSteps: 1,
      ...(signal ? { abortSignal: signal } : {}),
    })
  ).object;
