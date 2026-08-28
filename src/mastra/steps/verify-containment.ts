import { createStep } from "@mastra/core/workflows";

import { ContainmentExecutionResultSchema } from "../../approval/phase6-contracts.js";

export function createVerifyContainmentStep() {
  return createStep({
    id: "verify-containment",
    description:
      "Rejects any aggregate that lacks a persisted successful post-condition.",
    inputSchema: ContainmentExecutionResultSchema,
    outputSchema: ContainmentExecutionResultSchema,
    execute: async ({ inputData }) => {
      if (inputData.status !== "containment-succeeded") return inputData;
      return inputData.outcomes.every(
        (outcome) =>
          outcome.status === "completed" && outcome.verification === "verified",
      )
        ? inputData
        : {
            ...inputData,
            status: "containment-failed" as const,
            partial: inputData.outcomes.some(
              (outcome) => outcome.status === "completed",
            ),
          };
    },
  });
}
