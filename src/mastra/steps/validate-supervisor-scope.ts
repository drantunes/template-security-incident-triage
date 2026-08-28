import { createStep } from "@mastra/core/workflows";

import { DomainError } from "../../domain/errors.js";
import { InvestigationContextSchema } from "../../evidence/contracts.js";
import {
  invokeSocSupervisor,
  SupervisorValidationSchema,
  type SupervisorInvoker,
} from "../agents/soc-supervisor.js";
import { generateWithOneSchemaRetry } from "../agents/investigator-output.js";

export function createValidateSupervisorScopeStep(
  invoke: SupervisorInvoker = invokeSocSupervisor,
) {
  return createStep({
    id: "soc-supervisor-validate-scope",
    description:
      "Executes the bounded supervisor and validates one trusted investigation context.",
    inputSchema: InvestigationContextSchema,
    outputSchema: InvestigationContextSchema,
    execute: async ({ inputData, abortSignal }) => {
      const validation = await generateWithOneSchemaRetry(
        (attempt) => invoke(inputData, attempt, abortSignal),
        SupervisorValidationSchema,
      );
      if (validation.status !== "success")
        throw new DomainError("VALIDATION_FAILED");
      const expected = {
        scopeValidated: true,
        specialists: ["identity", "endpoint", "cloud"],
      };
      if (JSON.stringify(validation.output) !== JSON.stringify(expected))
        throw new DomainError("CONFLICT");
      return InvestigationContextSchema.parse(inputData);
    },
  });
}
