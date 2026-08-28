import { Agent } from "@mastra/core/agent";
import { z } from "zod";

import type { InvestigationContext } from "../../evidence/contracts.js";

import { cloudInvestigator } from "./cloud-investigator.js";
import { endpointInvestigator } from "./endpoint-investigator.js";
import { identityInvestigator } from "./identity-investigator.js";
import { UNTRUSTED_DATA_INSTRUCTIONS } from "./investigator-output.js";

export const socSupervisor = new Agent({
  id: "soc-supervisor",
  name: "SOC Supervisor",
  description:
    "Bounded coordinator for the three Phase 4 investigation specialists.",
  instructions: `${UNTRUSTED_DATA_INSTRUCTIONS}
Validate that every specialist request uses the same trusted tenant, incident, subject, and run.
The deterministic workflow owns fan-out, persistence, convergence, and ordering. Do not add capabilities.`,
  model: process.env.MASTRA_MODEL ?? "openai/gpt-4o-mini",
  maxRetries: 0,
  agents: { identityInvestigator, endpointInvestigator, cloudInvestigator },
  tools: {},
  defaultOptions: {
    maxSteps: 4,
    maxProcessorRetries: 0,
    modelSettings: {
      temperature: 0,
      timeout: { totalMs: 3_000, stepMs: 1_500 },
    },
  },
});

export const SupervisorValidationSchema = z
  .object({
    scopeValidated: z.literal(true),
    specialists: z.tuple([
      z.literal("identity"),
      z.literal("endpoint"),
      z.literal("cloud"),
    ]),
  })
  .strict();

export type SupervisorInvoker = (
  context: InvestigationContext,
  attempt: 1 | 2,
  signal?: AbortSignal,
) => Promise<unknown>;

export function supervisorPrompt(): string {
  return `Validate the fixed Phase 4 capability set without delegation or tool calls.
The deterministic workflow has already bound and validated the trusted scope server-side.
Return scopeValidated=true and specialists identity, endpoint, cloud in that order.`;
}

export const invokeSocSupervisor: SupervisorInvoker = async (
  _context,
  _attempt,
  signal,
) =>
  (
    await socSupervisor.generate(supervisorPrompt(), {
      structuredOutput: { schema: SupervisorValidationSchema },
      toolChoice: "none",
      maxSteps: 1,
      ...(signal ? { abortSignal: signal } : {}),
    })
  ).object;
