import { Mastra } from "@mastra/core/mastra";

import { smokeAgent } from "./agents/smoke-agent.js";
import { storage } from "./storage.js";
import { baselineWorkflow } from "./workflows/baseline-workflow.js";

export { storage } from "./storage.js";

export const mastra = new Mastra({
  agents: { smokeAgent },
  workflows: { baselineWorkflow },
  storage,
});
