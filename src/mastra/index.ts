import { Mastra } from "@mastra/core/mastra";

import { smokeAgent } from "./agents/smoke-agent.js";
import { identityInvestigator } from "./agents/identity-investigator.js";
import { endpointInvestigator } from "./agents/endpoint-investigator.js";
import { cloudInvestigator } from "./agents/cloud-investigator.js";
import { correlationAnalyst } from "./agents/correlation-analyst.js";
import { socSupervisor } from "./agents/soc-supervisor.js";
import { storage } from "./storage.js";
import { baselineWorkflow } from "./workflows/baseline-workflow.js";
import { incidentIngestionWorkflow } from "./workflows/incident-ingestion-workflow.js";
import { observability } from "./observability.js";

export { storage } from "./storage.js";

export const mastra = new Mastra({
  agents: {
    smokeAgent,
    identityInvestigator,
    endpointInvestigator,
    cloudInvestigator,
    correlationAnalyst,
    socSupervisor,
  },
  workflows: { baselineWorkflow, incidentIngestionWorkflow },
  storage,
  observability,
});
