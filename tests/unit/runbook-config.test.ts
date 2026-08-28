import { describe, expect, it } from "vitest";

import { readRunbookConfig } from "../../src/runbooks/config.js";

describe("runbook configuration", () => {
  it("uses an explicit local cache path and rejects empty or excessive values", () => {
    expect(readRunbookConfig({}).fastembedCacheDir).toBe(".cache/fastembed");
    expect(
      readRunbookConfig({ RUNBOOK_FASTEMBED_CACHE_DIR: "/tmp/phase3-model" })
        .fastembedCacheDir,
    ).toBe("/tmp/phase3-model");
    expect(() =>
      readRunbookConfig({ RUNBOOK_FASTEMBED_CACHE_DIR: " " }),
    ).toThrow("Invalid Phase 3 runbook configuration.");
    expect(() =>
      readRunbookConfig({ RUNBOOK_FASTEMBED_CACHE_DIR: "a".repeat(1_025) }),
    ).toThrow("Invalid Phase 3 runbook configuration.");
  });
});
