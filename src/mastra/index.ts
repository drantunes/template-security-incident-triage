import { Mastra } from "@mastra/core/mastra";
import { MastraAuthWorkos } from "@mastra/auth-workos";

import { smokeAgent } from "./agents/smoke-agent.js";
import { identityInvestigator } from "./agents/identity-investigator.js";
import { endpointInvestigator } from "./agents/endpoint-investigator.js";
import { cloudInvestigator } from "./agents/cloud-investigator.js";
import { correlationAnalyst } from "./agents/correlation-analyst.js";
import { socSupervisor } from "./agents/soc-supervisor.js";
import { responsePlanner } from "./agents/response-planner.js";
import { storage } from "./storage.js";
import { baselineWorkflow } from "./workflows/baseline-workflow.js";
import { incidentIngestionWorkflow } from "./workflows/incident-ingestion-workflow.js";
import { observability } from "./observability.js";

const runtimeAuth =
  process.env.DASHBOARD_AUTH_ENABLED === "true" &&
  process.env.WORKOS_API_KEY &&
  process.env.WORKOS_CLIENT_ID &&
  process.env.WORKOS_COOKIE_PASSWORD
    ? new MastraAuthWorkos({
        apiKey: process.env.WORKOS_API_KEY,
        clientId: process.env.WORKOS_CLIENT_ID,
        redirectUri: process.env.WORKOS_REDIRECT_URI,
        session: { cookiePassword: process.env.WORKOS_COOKIE_PASSWORD },
      })
    : undefined;

export { storage } from "./storage.js";

export const mastra = new Mastra({
  agents: {
    smokeAgent,
    identityInvestigator,
    endpointInvestigator,
    cloudInvestigator,
    correlationAnalyst,
    socSupervisor,
    responsePlanner,
  },
  workflows: { baselineWorkflow, incidentIngestionWorkflow },
  storage,
  observability,
  ...(runtimeAuth ? { server: { auth: runtimeAuth } } : {}),
});
