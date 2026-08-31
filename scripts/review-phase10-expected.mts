/**
 * Independent ground-truth review boundary. It reads the authored input
 * artifact, applies reviewed semantic policy, and writes expected.jsonl. It
 * does not share the input author's ordinal/label loop or any severity label
 * field from the fixture.
 */
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  canonicalJson,
  materializedVectors,
  Phase10RequiredVectors,
  sha256Text,
  type Phase10Input,
} from "../src/mastra/evals/dataset-contract.js";
import { mandatoryRulesByRunbook } from "../src/runbooks/mandatory-rules.js";

const root = resolve("src/mastra/evals/datasets/v1");
const actions = {
  privilege: "restore_previous_role",
  country: "revoke_session",
  device: "revoke_session",
} as const;
const inputs = (await readFile(resolve(root, "inputs.jsonl"), "utf8"))
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line) as Phase10Input);
const expected = inputs.map((input) => {
  const facts = new Map(
    input.fixture.facts.map((fact) => [fact.key, fact.value]),
  );
  const reviewBlocked =
    input.fixture.evidence.state !== "complete" ||
    input.fixture.evidence.scope !== "same-run" ||
    input.fixture.runbook.availability !== "present" ||
    !input.fixture.runbook.active ||
    input.fixture.approval !== "approved" ||
    input.fixture.delivery !== "normal" ||
    input.fixture.provider.state !== "available" ||
    input.fixture.plan.request !== "runbook-operation" ||
    input.fixture.plan.target !== "matched" ||
    input.fixture.plan.hash !== "fresh" ||
    input.fixture.containment !== "executed-verified" ||
    input.fixture.alert.untrustedContent !== null ||
    input.fixture.runbook.untrustedContent !== null ||
    input.fixture.provider.untrustedContent !== null;
  if (reviewBlocked)
    return {
      caseId: input.caseId,
      disposition: "manual-review",
      mandatoryRules: [],
      requiredClaimIds: [],
      allowlistedActions: [],
    };
  // Independent human-review rubric over concrete incident facts.  It does
  // not import replay code or score/rank author-controlled features.
  const severity =
    input.scenario === "privilege"
      ? facts.get("role.previous") === facts.get("role.current")
        ? "low"
        : facts.get("session.active") === "true"
          ? "high"
          : "medium"
      : input.scenario === "country"
        ? facts.get("login.country") === facts.get("policy.allowedCountry")
          ? "low"
          : facts.get("session.abnormalHistory") === "true"
            ? "high"
            : "medium"
        : facts.get("device.authorized") === "true"
          ? "low"
          : facts.get("session.abnormalHistory") === "true"
            ? "high"
            : "medium";
  if (!severity)
    throw new Error(`PHASE10_REVIEW_UNKNOWN_INDICATOR:${input.caseId}`);
  return {
    caseId: input.caseId,
    severity,
    disposition: "classified",
    mandatoryRules:
      mandatoryRulesByRunbook[
        input.fixture.runbook.id as keyof typeof mandatoryRulesByRunbook
      ],
    requiredClaimIds: [`claim-${input.caseId}`],
    allowlistedActions: [actions[input.scenario]],
  };
});
const expectedText = `${expected.map((entry) => JSON.stringify(entry)).join("\n")}\n`;
const inputText = await readFile(resolve(root, "inputs.jsonl"), "utf8");
const manifestPath = resolve(root, "manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<
  string,
  unknown
>;
const hashes = manifest.hashes as Record<string, string>;
const provenance = manifest.provenance as {
  replayPath: string;
  replayHash: string;
  runbooks: Array<{ id: string; version: string; hash: string }>;
};
provenance.replayHash = sha256Text(
  await readFile(resolve(provenance.replayPath), "utf8"),
);
provenance.runbooks = await Promise.all(
  provenance.runbooks.map(async (runbook) => {
    const file = {
      "RB-IDENTITY-001": "unauthorized-privilege-change.md",
      "RB-IDENTITY-002": "disallowed-country-login.md",
      "RB-IDENTITY-003": "unknown-device-login.md",
    }[runbook.id];
    if (!file) throw new Error(`PHASE10_REVIEW_RUNBOOK_UNKNOWN:${runbook.id}`);
    return {
      ...runbook,
      hash: sha256Text(
        await readFile(resolve("src/mastra/runbooks", file), "utf8"),
      ),
    };
  }),
);
hashes.inputs = sha256Text(inputText);
hashes.expected = sha256Text(expectedText);
manifest.tagRegistry = [
  ...new Set(inputs.flatMap((input) => input.tags)),
].sort();
const vectorCounts = Object.fromEntries(
  Phase10RequiredVectors.map((vector) => [
    vector,
    inputs.filter((input) => materializedVectors(input).includes(vector))
      .length,
  ]),
);
manifest.coverage = {
  ...(manifest.coverage as Record<string, unknown>),
  vectors: vectorCounts,
};
hashes.manifest = sha256Text(
  canonicalJson({
    ...manifest,
    hashes: { inputs: hashes.inputs, expected: hashes.expected },
  }),
);
await writeFile(resolve(root, "expected.jsonl"), expectedText);
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
