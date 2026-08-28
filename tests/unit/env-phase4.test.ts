import { describe, expect, it } from "vitest";

import { readPhase4Config } from "../../src/env.js";

describe("Phase 4 configuration", () => {
  it("uses the approved model and bounded per-source timeout defaults", () => {
    expect(readPhase4Config({})).toEqual({
      model: "openai/gpt-4o-mini",
      timeouts: { identity: 1_500, endpoint: 1_500, cloud: 1_500 },
    });
  });

  it("rejects invalid source budgets", () => {
    expect(() => readPhase4Config({ EVIDENCE_CLOUD_TIMEOUT_MS: "99" })).toThrow(
      "Invalid Phase 4 configuration.",
    );
  });
});
