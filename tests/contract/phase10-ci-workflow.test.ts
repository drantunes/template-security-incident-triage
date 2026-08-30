import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const exec = promisify(execFile);

describe("Phase 10 CI workflow", () => {
  it("keeps the gate log outside the checkout and fails closed on pipe or approval failure", async () => {
    const workflow = await readFile(".github/workflows/ci.yml", "utf8");
    expect(workflow).toContain("shell: bash");
    expect(workflow).toContain("set -o pipefail");
    expect(workflow).toContain('phase10_log="$RUNNER_TEMP/phase10-ci.log"');
    expect(workflow).toContain('npm run phase10:ci 2>&1 | tee "$phase10_log"');
    expect(workflow).toContain(
      'grep -Fx "phase10-approved=true" "$phase10_log"',
    );
    expect(workflow).not.toContain("| tee phase10-ci.log");
    expect(workflow).toContain(
      "if: ${{ success() && steps.phase10.outputs.approved == 'true' }}",
    );

    const runnerTemp = await mkdtemp(join(tmpdir(), "phase10-ci-log-"));
    const phase10Log = join(runnerTemp, "phase10-ci.log");
    try {
      const run = (script: string) =>
        exec("bash", ["-c", script], {
          cwd: process.cwd(),
          env: { ...process.env, PHASE10_LOG: phase10Log },
        });
      await expect(
        run(
          'set -euo pipefail; printf "phase10-approved=true\\n" | tee "$PHASE10_LOG"; grep -Fx "phase10-approved=true" "$PHASE10_LOG"',
        ),
      ).resolves.toBeDefined();
      expect(await readFile(phase10Log, "utf8")).toBe(
        "phase10-approved=true\n",
      );

      // A failing producer that prints a positive marker must still fail: the
      // old `npm run ... | tee phase10-ci.log` accepted this false green.
      await expect(
        run(
          'set -euo pipefail; (printf "phase10-approved=true\\n"; exit 3) | tee "$PHASE10_LOG"; grep -Fx "phase10-approved=true" "$PHASE10_LOG"',
        ),
      ).rejects.toMatchObject({ code: 3 });
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
  });
});
