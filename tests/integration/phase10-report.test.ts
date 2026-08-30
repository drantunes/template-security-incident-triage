import { execFile } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { sha256Canonical } from "../../src/mastra/evals/dataset-contract.js";

const exec = promisify(execFile);
const fixedClock = "2026-08-30T00:00:00.000Z";

describe("Phase 10 approved report pipeline", () => {
  it("requires ancestry history in CI while retaining fail-closed provenance", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase10-shallow-history-"));
    const seed = join(root, "seed");
    const origin = join(root, "origin.git");
    const shallow = join(root, "shallow");
    try {
      await exec("git", ["init", "-b", "main", seed]);
      await exec("git", [
        "-C",
        seed,
        "config",
        "user.email",
        "phase10@example.test",
      ]);
      await exec("git", ["-C", seed, "config", "user.name", "Phase 10"]);
      await writeFile(join(seed, "provenance"), "origin\n", "utf8");
      await exec("git", ["-C", seed, "add", "provenance"]);
      await exec("git", ["-C", seed, "commit", "-m", "origin"]);
      const originCommit = (
        await exec("git", ["-C", seed, "rev-parse", "HEAD"])
      ).stdout.trim();
      await writeFile(join(seed, "provenance"), "descendant\n", "utf8");
      await exec("git", ["-C", seed, "commit", "-am", "descendant"]);
      await exec("git", ["clone", "--bare", seed, origin]);
      await exec("git", ["clone", "--depth", "1", `file://${origin}`, shallow]);
      const head = (
        await exec("git", ["-C", shallow, "rev-parse", "HEAD"])
      ).stdout.trim();
      await expect(
        exec("git", [
          "-C",
          shallow,
          "merge-base",
          "--is-ancestor",
          originCommit,
          head,
        ]),
      ).rejects.toBeDefined();
      await exec("git", [
        "-C",
        shallow,
        "fetch",
        "--depth",
        "2",
        "origin",
        "main",
      ]);
      await expect(
        exec("git", [
          "-C",
          shallow,
          "merge-base",
          "--is-ancestor",
          originCommit,
          head,
        ]),
      ).resolves.toBeDefined();
      expect(await readFile(".github/workflows/ci.yml", "utf8")).toMatch(
        /actions\/checkout@v4\s+with:\s+fetch-depth: 0/u,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("anchors the E2E clock and report window to B1 instead of wall time", async () => {
    const [runtime, report, migration] = await Promise.all([
      readFile("src/demo/runtime.ts", "utf8"),
      readFile("scripts/phase10-report.mts", "utf8"),
      readFile(
        "src/db/migrations/0014-phase10-provider-observed-at.ts",
        "utf8",
      ),
    ]);
    expect(runtime).toContain(`fixedNow = "${fixedClock}"`);
    expect(runtime).not.toContain("Date.now");
    expect(report).toContain(
      "exerciseProductE2EWithReproducibleClock(loaded.manifest.clock)",
    );
    expect(report).toContain("const window = reportWindow(clock)");
    expect(report).not.toContain('from: "2026-08-30T00:00:00.000Z"');
    expect(migration).not.toContain("strftime");
  });

  it("returns structured argument failures before dataset or report work", async () => {
    const invoke = (arguments_: readonly string[]) =>
      exec(
        process.execPath,
        ["--import", "tsx", "scripts/phase10-report.mts", ...arguments_],
        { timeout: 10_000 },
      ).then(
        () => undefined,
        (error: unknown) => error,
      );

    const invalidDataset = await invoke(["--dataset", "v2"]);
    expect(invalidDataset).toMatchObject({
      code: 2,
      stderr: expect.stringContaining("PHASE10_REPORT_ARGUMENT_INVALID"),
    });
    expect((invalidDataset as { stderr: string }).stderr).not.toContain(
      "UnhandledPromiseRejection",
    );

    const missingDataset = await invoke(["--dataset"]);
    expect(missingDataset).toMatchObject({
      code: 2,
      stderr: expect.stringContaining(
        "PHASE10_REPORT_ARGUMENT_MISSING:--dataset",
      ),
    });

    const mixedInvalid = await invoke(["--dataset", "v2", "--output"]);
    expect(mixedInvalid).toMatchObject({
      code: 2,
      stderr: expect.stringContaining(
        "PHASE10_REPORT_ARGUMENT_MISSING:--output",
      ),
    });
  });

  it("uses LibSQL authority and the registered Mastra scorer API without mutating the approved dataset", async () => {
    const root = await mkdtemp(join(tmpdir(), "phase10-report-test-"));
    const copiedDataset = join(root, "dataset");
    const output = join(root, "report-a");
    const secondOutput = join(root, "report-b");
    try {
      await cp("src/mastra/evals/datasets/v1", copiedDataset, {
        recursive: true,
      });
      const manifestPath = join(copiedDataset, "manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
        approvedBy: string | null;
        approvedAt: string | null;
        approvalStatus: "pending" | "approved";
        hashes: { inputs: string; expected: string; manifest: string };
        provenance: { independentReviewers: string[] };
      };
      manifest.approvalStatus = "approved";
      manifest.approvedBy = "Diego";
      manifest.approvedAt = fixedClock;
      manifest.provenance.independentReviewers = ["temporary-test-reviewer"];
      manifest.hashes.manifest = sha256Canonical({
        ...manifest,
        hashes: {
          inputs: manifest.hashes.inputs,
          expected: manifest.hashes.expected,
        },
      });
      await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`, "utf8");
      await exec(
        process.execPath,
        [
          "--import",
          "tsx",
          "scripts/phase10-report.mts",
          "--dataset-root",
          copiedDataset,
          "--output",
          output,
        ],
        { timeout: 60_000 },
      );
      await exec(
        process.execPath,
        [
          "--import",
          "tsx",
          "scripts/phase10-report.mts",
          "--dataset-root",
          copiedDataset,
          "--output",
          secondOutput,
        ],
        { timeout: 60_000 },
      );
      const [firstJson, secondJson, firstMarkdown, secondMarkdown] =
        await Promise.all([
          readFile(join(output, "report.json")),
          readFile(join(secondOutput, "report.json")),
          readFile(join(output, "report.md")),
          readFile(join(secondOutput, "report.md")),
        ]);
      expect(JSON.parse(firstJson.toString())).toEqual(
        JSON.parse(secondJson.toString()),
      );
      expect(firstJson.equals(secondJson)).toBe(true);
      expect(firstMarkdown.equals(secondMarkdown)).toBe(true);
      const report = JSON.parse(
        await readFile(join(output, "report.json"), "utf8"),
      ) as {
        scores: Record<string, { passed: boolean }>;
        e2e: Array<{
          scenario: "privilege" | "country" | "device";
          metrics: Record<
            string,
            {
              sampleCount: number;
              value: number | null;
              distribution?: { p50: number; p95: number; max: number };
            }
          >;
          breakdowns: {
            provider: {
              status: Record<string, number>;
              operation: Record<string, number>;
              retries: number;
            };
            guardrail: {
              status: Record<string, number>;
              reason: Record<string, number>;
            };
            containment: {
              attempted: number;
              executed: number;
              verified: number;
              attemptToVerification: {
                sampleCount: number;
                value: number | null;
              };
            };
            escalation: {
              expected: string;
              observed: string;
              matched: boolean;
            };
            audit: { requiredBoundaries: number; completeManifests: number };
          };
        }>;
        cases: Array<{ scorers: unknown[] }>;
        analytics: { confusionLedger: Record<string, number> };
        envelope: {
          provenance: {
            commitSha: string;
            worktree: { dirty: boolean; statusSha256: string };
          };
          runtime: { node: string; os: string };
          dependencies: {
            lockfileSha256: string;
            resolved: Record<string, string>;
          };
          inputs: {
            dataset: { id: string; schemaVersion: number; hashes: unknown };
            promptArtifact: { id: string; hash: string };
            model: { id: string; version: string };
            replay: { id: string; hash: string };
            runbooks: unknown[];
            seed: string;
            clock: string;
          };
        };
        aggregates: { cases: number; confusion: Record<string, number> };
        execution: {
          externalExecution: string;
          replay: { seed: string; clock: string; clockProjection: string };
          exitPrecedence: string[];
        };
      };
      expect(Object.keys(report.scores).sort()).toEqual([
        "disposition",
        "phase10Attribution",
        "phase10Compliance",
        "phase10Hallucination",
        "phase10Safety",
        "phase10Severity",
      ]);
      expect(Object.values(report.scores).every((score) => score.passed)).toBe(
        true,
      );
      expect(report.envelope).toMatchObject({
        provenance: {
          commitSha: (await exec("git", ["rev-parse", "HEAD"])).stdout.trim(),
          worktree: { dirty: false, statusSha256: expect.any(String) },
        },
        runtime: {
          node: expect.stringMatching(/^v\d+/u),
          os: expect.any(String),
        },
        dependencies: {
          lockfileSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
          resolved: {
            "@duckdb/node-api": "1.5.5-r.4",
            "@mastra/core": "1.63.0",
          },
        },
        inputs: {
          dataset: { id: "phase10-dataset-v1", schemaVersion: 1 },
          model: { id: "openai/gpt-4o-mini", version: "offline-fixture-v1" },
          seed: "phase10-v1-offline-seed",
          clock: fixedClock,
        },
      });
      expect(report.aggregates).toMatchObject({ cases: 72 });
      expect(
        Object.values(report.aggregates.confusion).reduce((a, b) => a + b, 0),
      ).toBe(72);
      expect(report.execution).toMatchObject({
        externalExecution: "not-executed",
        replay: {
          seed: "phase10-v1-offline-seed",
          clock: fixedClock,
          clockProjection: "phase10-reproducible-observed-clock-v1",
        },
      });
      expect(report.execution.exitPrecedence).toEqual([
        "trace-redaction:6",
        "threshold:5",
        "infrastructure:4",
        "integrity:3",
        "argument:2",
      ]);
      expect(report.cases).toHaveLength(72);
      expect(report.cases.every((item) => item.scorers.length === 5)).toBe(
        true,
      );
      expect(
        Object.values(report.analytics.confusionLedger).reduce(
          (total, count) => total + count,
          0,
        ),
      ).toBe(72);
      expect(report.e2e).toHaveLength(3);
      for (const run of report.e2e) {
        for (const metric of [
          "triage_latency",
          "step_duration",
          "provider_failure_rate",
          "escalation_accuracy",
          "approval_latency",
          "guardrail_block_rate",
          "audit_trace_completeness",
        ]) {
          expect(run.metrics[metric]?.sampleCount).toBeGreaterThan(0);
          expect(run.metrics[metric]?.value).not.toBeNull();
        }
        for (const metric of [
          "triage_latency",
          "step_duration",
          "approval_latency",
        ])
          expect(run.metrics[metric]?.distribution).toMatchObject({
            p50: expect.any(Number),
            p95: expect.any(Number),
            max: expect.any(Number),
          });
        expect(run.metrics.provider_failure_rate?.value).toBe(0);
        expect(run.metrics.guardrail_block_rate?.value).toBe(0);
        expect(run.metrics.escalation_accuracy?.value).toBe(1);
        expect(run.metrics.audit_trace_completeness?.value).toBe(1);
        expect(run.metrics.containment_execution_rate).toMatchObject(
          run.scenario === "privilege"
            ? { sampleCount: expect.any(Number), value: 1 }
            : { sampleCount: 0, value: null },
        );
        expect(
          Object.values(run.breakdowns.provider.status).reduce(
            (a, b) => a + b,
            0,
          ),
        ).toBe(run.metrics.provider_failure_rate?.sampleCount);
        expect(
          Object.values(run.breakdowns.guardrail.status).reduce(
            (a, b) => a + b,
            0,
          ),
        ).toBe(run.metrics.guardrail_block_rate?.sampleCount);
        expect(run.breakdowns.escalation).toMatchObject({
          expected:
            run.scenario === "privilege"
              ? "approved"
              : run.scenario === "country"
                ? "rejected"
                : "expired",
          matched: true,
        });
        expect(run.breakdowns.audit.requiredBoundaries).toBeGreaterThan(1);
        expect(run.breakdowns.audit.completeManifests).toBe(
          run.breakdowns.audit.requiredBoundaries,
        );
        expect(run.breakdowns.containment.attempted).toBe(
          run.metrics.containment_execution_rate?.sampleCount,
        );
      }
      const committed = JSON.parse(
        await readFile("src/mastra/evals/datasets/v1/manifest.json", "utf8"),
      ) as { approvalStatus: string };
      expect(committed.approvalStatus).toBe("approved");
      await expect(
        exec(
          process.execPath,
          [
            "--import",
            "tsx",
            "scripts/phase10-report.mts",
            "--dataset-root",
            copiedDataset,
            "--output",
            join(root, "authority-gap"),
          ],
          {
            timeout: 60_000,
            env: { ...process.env, PHASE10_TEST_AUTHORITY_GAP: "privilege" },
          },
        ),
      ).rejects.toMatchObject({
        stderr: expect.stringContaining(
          "PHASE10_E2E_AUTHORITY_PRIVILEGE_INVALID",
        ),
        code: 6,
      });
      // Each fault is injected by the corresponding concrete capture path;
      // no assertion passes a hand-built scanner surface.
      for (const surface of [
        "captured-logs:privilege",
        "trace-public-api:privilege",
        "timeline-rows:privilege",
        "provider-delivery-rows:privilege",
        "approval-rows:privilege",
        "authority-evidence-rows:privilege",
        "outbox-rows:privilege",
        "duckdb-read-model:privilege",
        "duckdb-read-model:offline",
        "libsql-eval-results",
        "official-score-ledger",
        "report.json",
        "report.md",
      ])
        await expect(
          exec(
            process.execPath,
            [
              "--import",
              "tsx",
              "scripts/phase10-report.mts",
              "--dataset-root",
              copiedDataset,
              "--output",
              join(root, `leaked-${surface.replaceAll(":", "-")}`),
            ],
            {
              timeout: 60_000,
              env: {
                ...process.env,
                PHASE10_TEST_REDACTION_LEAK_SURFACE: surface,
              },
            },
          ),
        ).rejects.toMatchObject({
          stderr: expect.stringContaining("PHASE10_REDACTION_LEAK"),
          code: 6,
        });

      // Train/dev observations remain ledger evidence but cannot influence the
      // frozen test-only macro-F1 gate.
      const mutatedOutput = join(root, "report-mutated-case");
      await exec(
        process.execPath,
        [
          "--import",
          "tsx",
          "scripts/phase10-report.mts",
          "--dataset-root",
          copiedDataset,
          "--output",
          mutatedOutput,
        ],
        {
          timeout: 60_000,
          env: {
            ...process.env,
            PHASE10_TEST_OBSERVED_MUTATION: "p10-v1-privilege-01",
          },
        },
      );
      const mutated = JSON.parse(
        await readFile(join(mutatedOutput, "report.json"), "utf8"),
      ) as {
        cases: Array<{ caseId: string; scorers: Array<{ passed: boolean }> }>;
        aggregates: { confusion: Record<string, number> };
      };
      expect(
        mutated.cases
          .find((item) => item.caseId === "p10-v1-privilege-01")
          ?.scorers.some((score) => !score.passed),
      ).toBe(true);
      expect(mutated.aggregates.confusion["low->medium"]).toBe(1);
      await expect(
        exec(
          process.execPath,
          [
            "--import",
            "tsx",
            "scripts/phase10-report.mts",
            "--dataset-root",
            copiedDataset,
            "--output",
            join(root, "report-mutated-test"),
          ],
          {
            timeout: 60_000,
            env: {
              ...process.env,
              PHASE10_TEST_OBSERVED_MUTATION:
                "p10-v1-privilege-17,p10-v1-privilege-18,p10-v1-privilege-19",
            },
          },
        ),
      ).rejects.toMatchObject({ code: 5 });

      // Independent terminal gates are all reported before precedence chooses
      // redaction (6) over threshold (5); neither cause may be lost.
      const combined = await exec(
        process.execPath,
        [
          "--import",
          "tsx",
          "scripts/phase10-report.mts",
          "--dataset-root",
          copiedDataset,
          "--output",
          join(root, "report-threshold-and-redaction-stderr"),
        ],
        {
          timeout: 60_000,
          env: {
            ...process.env,
            PHASE10_TEST_OBSERVED_MUTATION:
              "p10-v1-privilege-17,p10-v1-privilege-18,p10-v1-privilege-19",
            PHASE10_TEST_REDACTION_LEAK_SURFACE: "report.json",
          },
        },
      ).then(
        () => undefined,
        (error: unknown) => error,
      );
      expect(combined).toMatchObject({
        code: 6,
        stderr: expect.stringContaining("PHASE10_REDACTION_LEAK"),
      });
      expect((combined as { stderr: string }).stderr).toContain(
        "PHASE10_THRESHOLD_FAILED",
      );

      // Dataset provenance remains the immutable authoring snapshot, while
      // the report records the actual checked-out descendant. An unrelated
      // origin and a dirty checkout must both fail before replay/output.
      const approvedManifest = await readFile(manifestPath, "utf8");
      const unrelated = JSON.parse(approvedManifest);
      unrelated.provenance.originCommit = "f".repeat(40);
      unrelated.hashes.manifest = sha256Canonical({
        ...unrelated,
        hashes: {
          inputs: unrelated.hashes.inputs,
          expected: unrelated.hashes.expected,
        },
      });
      await writeFile(manifestPath, `${JSON.stringify(unrelated)}\n`, "utf8");
      await expect(
        exec(
          process.execPath,
          [
            "--import",
            "tsx",
            "scripts/phase10-report.mts",
            "--dataset-root",
            copiedDataset,
            "--output",
            join(root, "unrelated-origin"),
          ],
          { timeout: 60_000 },
        ),
      ).rejects.toMatchObject({
        code: 3,
        stderr: expect.stringContaining("PHASE10_WORKTREE_COMMIT_MISMATCH"),
      });
      await writeFile(manifestPath, approvedManifest, "utf8");

      const dirtyWorktree = await mkdtemp(
        join(process.cwd(), "phase10-report-dirty-"),
      );
      try {
        await writeFile(join(dirtyWorktree, "marker"), "test\n", "utf8");
        await expect(
          exec(
            process.execPath,
            [
              "--import",
              "tsx",
              "scripts/phase10-report.mts",
              "--dataset-root",
              copiedDataset,
              "--output",
              join(root, "dirty-worktree"),
            ],
            { timeout: 60_000 },
          ),
        ).rejects.toMatchObject({
          code: 3,
          stderr: expect.stringContaining("PHASE10_WORKTREE_DIRTY"),
        });
      } finally {
        await rm(dirtyWorktree, { recursive: true, force: true });
      }

      // A schema-valid JSON document with incomplete approval fields is a
      // manifest integrity failure, never report infrastructure.
      const malformed = JSON.parse(await readFile(manifestPath, "utf8"));
      malformed.approvalStatus = "approved";
      malformed.approvedBy = null;
      await writeFile(manifestPath, `${JSON.stringify(malformed)}\n`, "utf8");
      await expect(
        exec(
          process.execPath,
          [
            "--import",
            "tsx",
            "scripts/phase10-report.mts",
            "--dataset-root",
            copiedDataset,
          ],
          { timeout: 60_000 },
        ),
      ).rejects.toMatchObject({ code: 3 });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 120_000);
});
