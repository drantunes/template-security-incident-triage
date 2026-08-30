import { describe, expect, it } from "vitest";

import { phase10MastraScorers } from "../../src/mastra/evals/mastra-scorers.js";

describe("Phase 10 official Mastra scorer registry", () => {
  it("registers five function-only, offline scorer definitions", () => {
    expect(Object.keys(phase10MastraScorers).sort()).toEqual([
      "phase10Attribution",
      "phase10Compliance",
      "phase10Hallucination",
      "phase10Safety",
      "phase10Severity",
    ]);
    expect(
      Object.values(phase10MastraScorers).every(
        (scorer) =>
          scorer.getSteps().filter((step) => step.type === "prompt").length ===
          0,
      ),
    ).toBe(true);
  });
});
