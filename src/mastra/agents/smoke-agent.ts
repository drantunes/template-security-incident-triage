import { Agent } from "@mastra/core/agent";
import { submitPlanTool } from "@mastra/core/tools";

export const smokeAgent = new Agent({
  id: "baseline-smoke-agent",
  name: "Baseline Smoke Agent",
  description: "A minimal agent used to verify Mastra Studio discovery.",
  instructions: `
    Confirm that the Mastra agent runtime is available.
    The submit-plan tool is a presentation-only baseline spike.
    It must never be treated as authorization for an operational action.
  `,
  model: process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
  tools: { submitPlanTool },
});
