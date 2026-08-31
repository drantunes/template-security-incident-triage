import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertDatasetContract,
  sha256Text,
  type Phase10Expected,
  type Phase10Input,
  type Phase10Manifest,
} from "./dataset-contract.js";

const datasetDirectory = join(
  dirname(fileURLToPath(import.meta.url)),
  "datasets",
  "v1",
);

function parseJsonLines(text: string): unknown[] {
  return text
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as unknown);
}

export async function loadPhase10Dataset(
  options: Readonly<{ datasetDirectory?: string; projectRoot?: string }> = {},
): Promise<
  Readonly<{
    manifest: Phase10Manifest;
    inputs: readonly Phase10Input[];
    expected: readonly Phase10Expected[];
  }>
> {
  const directory = options.datasetDirectory ?? datasetDirectory;
  const [manifestText, inputText, expectedText] = await Promise.all([
    readFile(join(directory, "manifest.json"), "utf8"),
    readFile(join(directory, "inputs.jsonl"), "utf8"),
    readFile(join(directory, "expected.jsonl"), "utf8"),
  ]);
  const loaded = assertDatasetContract({
    manifest: JSON.parse(manifestText) as unknown,
    inputs: parseJsonLines(inputText),
    expected: parseJsonLines(expectedText),
    inputText,
    expectedText,
  });
  await assertProductProvenance(
    loaded.manifest,
    options.projectRoot ?? join(datasetDirectory, "..", "..", "..", "..", ".."),
  );
  return loaded;
}

async function assertProductProvenance(
  manifest: Phase10Manifest,
  root: string,
): Promise<void> {
  const prompt = await readFile(
    join(root, manifest.provenance.promptPath),
    "utf8",
  );
  if (sha256Text(prompt) !== manifest.provenance.promptHash)
    throw new Error("PHASE10_DATASET_PROMPT_PROVENANCE_INVALID");
  const replay = await readFile(
    join(root, manifest.provenance.replayPath),
    "utf8",
  );
  if (sha256Text(replay) !== manifest.provenance.replayHash)
    throw new Error("PHASE10_DATASET_REPLAY_PROVENANCE_INVALID");
  for (const runbook of manifest.provenance.runbooks) {
    const source = {
      "RB-IDENTITY-001": "unauthorized-privilege-change.md",
      "RB-IDENTITY-002": "disallowed-country-login.md",
      "RB-IDENTITY-003": "unknown-device-login.md",
    }[runbook.id];
    if (!source) throw new Error("PHASE10_DATASET_RUNBOOK_PROVENANCE_INVALID");
    const text = await readFile(
      join(root, "src", "mastra", "runbooks", source),
      "utf8",
    );
    if (sha256Text(text) !== runbook.hash)
      throw new Error("PHASE10_DATASET_RUNBOOK_PROVENANCE_INVALID");
  }
}

export function assertApprovedForObservedRun(manifest: Phase10Manifest): void {
  if (
    manifest.approvalStatus !== "approved" ||
    manifest.approvedBy !== "Diego" ||
    !manifest.approvedAt
  )
    throw new Error("PHASE10_DATASET_HITL_PENDING");
}
