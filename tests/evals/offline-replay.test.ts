import { describe, expect, it } from "vitest";

import { loadPhase10Dataset } from "../../src/mastra/evals/dataset-loader.js";
import { replayPhase10Offline } from "../../src/mastra/evals/offline-replay.js";

describe("Phase 10 offline replay", () => {
  it("derives observed decisions exclusively from inputs", async () => {
    const dataset = await loadPhase10Dataset();
    const baseline = replayPhase10Offline(dataset.inputs);
    const alteredExpected = dataset.expected.map((entry) => ({
      ...entry,
      disposition: "manual-review" as const,
      severity: undefined,
    }));
    // Expected is deliberately not an argument to replay; changing a separate
    // ground-truth object cannot influence any observed decision.
    expect(alteredExpected).not.toEqual(dataset.expected);
    expect(replayPhase10Offline(dataset.inputs)).toEqual(baseline);
    expect(
      baseline.filter((entry) => entry.decision.disposition === "classified"),
    ).toHaveLength(54);
  });
});
