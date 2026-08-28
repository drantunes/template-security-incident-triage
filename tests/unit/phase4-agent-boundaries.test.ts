import { describe, expect, it } from "vitest";

import { cloudInvestigator } from "../../src/mastra/agents/cloud-investigator.js";
import { correlationAnalyst } from "../../src/mastra/agents/correlation-analyst.js";
import { endpointInvestigator } from "../../src/mastra/agents/endpoint-investigator.js";
import { identityInvestigator } from "../../src/mastra/agents/identity-investigator.js";
import { socSupervisor } from "../../src/mastra/agents/soc-supervisor.js";
import { incidentIngestionWorkflow } from "../../src/mastra/workflows/incident-ingestion-workflow.js";

describe("Phase 4 capability boundaries and Studio graph", () => {
  it("gives each specialist exactly one domain-specific read tool", async () => {
    expect(
      Object.keys(await identityInvestigator.getToolsForExecution({})),
    ).toEqual(["identityReadTool"]);
    expect(
      Object.keys(await endpointInvestigator.getToolsForExecution({})),
    ).toEqual(["endpointReadTool"]);
    expect(
      Object.keys(await cloudInvestigator.getToolsForExecution({})),
    ).toEqual(["cloudReadTool"]);
    expect(
      Object.keys(await correlationAnalyst.getToolsForExecution({})),
    ).toEqual([]);
  });

  it("bounds the supervisor to the three specialists and no external tool", async () => {
    const tools = Object.keys(
      await socSupervisor.getToolsForExecution({}),
    ).sort();
    expect(tools).toEqual([
      "agent-cloudInvestigator",
      "agent-endpointInvestigator",
      "agent-identityInvestigator",
    ]);
    expect(tools.join(" ")).not.toMatch(
      /contain|http|shell|sql|browser|filesystem/iu,
    );
  });

  it("exposes one three-branch parallel node before correlation and RAG", () => {
    const graph = incidentIngestionWorkflow.stepGraph;
    const parallelIndex = graph.findIndex((entry) => entry.type === "parallel");
    const correlationIndex = graph.findIndex(
      (entry) => entry.type === "step" && entry.step.id === "correlate-events",
    );
    const retrievalIndex = graph.findIndex(
      (entry) => entry.type === "step" && entry.step.id === "retrieve-runbook",
    );
    expect(parallelIndex).toBeGreaterThan(0);
    expect(correlationIndex).toBeGreaterThan(parallelIndex);
    expect(retrievalIndex).toBeGreaterThan(correlationIndex);
    const parallel = graph[parallelIndex];
    expect(parallel?.type).toBe("parallel");
    if (parallel?.type === "parallel") {
      expect(
        parallel.steps.map((entry) =>
          entry.type === "step" ? entry.step.id : "unexpected",
        ),
      ).toEqual([
        "gather-identity-evidence",
        "gather-endpoint-evidence",
        "gather-cloud-evidence",
      ]);
    }
  });
});
