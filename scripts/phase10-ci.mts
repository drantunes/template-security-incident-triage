import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const exec = promisify(execFile);
const manifestPath = "src/mastra/evals/datasets/v1/manifest.json";
const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
  approvalStatus: string;
  approvedBy: string | null;
};
const approved =
  manifest.approvalStatus === "approved" && manifest.approvedBy === "Diego";
if (!approved) {
  const result = await exec(process.execPath, [
    "--import",
    "tsx",
    "scripts/phase10-report.mts",
    "--dataset",
    "v1",
    "--output",
    ".mastra/ci-phase10-pending",
  ]).catch((error: { code?: number; stderr?: string }) => error);
  if (
    result.code !== 3 ||
    !result.stderr?.includes("PHASE10_DATASET_HITL_PENDING")
  )
    throw new Error("PHASE10_CI_PENDING_GATE_INVALID");
  console.log("phase10-approved=false");
  process.exit(0);
}
await exec(process.execPath, [
  "--import",
  "tsx",
  "scripts/phase10-report.mts",
  "--dataset",
  "v1",
  "--output",
  ".mastra/ci-phase10-a",
]);
await exec(process.execPath, [
  "--import",
  "tsx",
  "scripts/phase10-report.mts",
  "--dataset",
  "v1",
  "--output",
  ".mastra/ci-phase10-b",
]);
const [left, right] = await Promise.all([
  readFile(".mastra/ci-phase10-a/report.json"),
  readFile(".mastra/ci-phase10-b/report.json"),
]);
if (!left.equals(right)) throw new Error("PHASE10_CI_NONDETERMINISTIC");
if (!createHash("sha256").update(left).digest("hex"))
  throw new Error("PHASE10_CI_REPORT_HASH_INVALID");
console.log("phase10-approved=true");
