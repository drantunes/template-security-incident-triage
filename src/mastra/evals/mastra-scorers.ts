import { createScorer } from "@mastra/core/evals";

import type { Phase10Expected, Phase10Input } from "./dataset-contract.js";
import {
  attributionScore,
  complianceScore,
  hallucinationScore,
  safetyScore,
  severityScore,
  type Phase10Observed,
  type Phase10Score,
  type Phase10Authority,
} from "./scorers.js";

/** Serializable target passed to Mastra's official scorer registry. */
export type Phase10EvalTarget = Readonly<{
  inputs: readonly Phase10Input[];
  expected: readonly Phase10Expected[];
  observed: readonly Phase10Observed[];
  authority: Phase10Authority;
}>;
type Resolver = (target: Phase10EvalTarget) => Phase10Score;

function targetFromOutput(output: unknown): Phase10EvalTarget | undefined {
  if (!output || typeof output !== "object") return undefined;
  const candidate = output as Partial<Phase10EvalTarget>;
  return Array.isArray(candidate.inputs) &&
    Array.isArray(candidate.expected) &&
    Array.isArray(candidate.observed)
    ? (candidate as Phase10EvalTarget)
    : undefined;
}
function phase10Scorer(id: string, description: string, resolve: Resolver) {
  return createScorer({ id, description }).generateScore(({ run }) => {
    const target = targetFromOutput(run.output);
    if (!target) return 0;
    const score = resolve(target);
    // Mastra gates use 1/0 semantics.  The exact numerator/denominator is
    // retained by the deterministic scorer contract and the LibSQL ledger;
    // the public Mastra execution is the authoritative pass/fail invocation.
    return score.passed ? 1 : 0;
  });
}
const targets = {
  severity: (target: Phase10EvalTarget) =>
    severityScore(target.inputs, target.expected, target.observed),
  attribution: (target: Phase10EvalTarget) =>
    attributionScore(
      target.inputs,
      target.expected,
      target.observed,
      target.authority,
    ),
  compliance: (target: Phase10EvalTarget) =>
    complianceScore(
      target.inputs,
      target.expected,
      target.observed,
      target.authority,
    ),
  hallucination: (target: Phase10EvalTarget) =>
    hallucinationScore(
      target.inputs,
      target.expected,
      target.observed,
      target.authority,
    ),
  safety: (target: Phase10EvalTarget) =>
    safetyScore(
      target.inputs,
      target.expected,
      target.observed,
      target.authority,
    ),
} as const;

/** Same evidence-bearing contracts used by the registered Mastra scorers. */
export function evaluatePhase10Official(target: Phase10EvalTarget) {
  return Object.freeze({
    severity: targets.severity(target),
    attribution: targets.attribution(target),
    compliance: targets.compliance(target),
    hallucination: targets.hallucination(target),
    safety: targets.safety(target),
  });
}

export const phase10MastraScorers = {
  phase10Severity: phase10Scorer(
    "phase10-severity-v1",
    "Offline severity gate",
    targets.severity,
  ),
  phase10Attribution: phase10Scorer(
    "phase10-attribution-v1",
    "Offline attribution gate",
    targets.attribution,
  ),
  phase10Compliance: phase10Scorer(
    "phase10-compliance-v1",
    "Offline runbook compliance gate",
    targets.compliance,
  ),
  phase10Hallucination: phase10Scorer(
    "phase10-hallucination-v1",
    "Offline unsupported-claim gate",
    targets.hallucination,
  ),
  phase10Safety: phase10Scorer(
    "phase10-safety-v1",
    "Offline safety gate",
    targets.safety,
  ),
} as const;

/**
 * Runs every registered scorer through Mastra's public scorer API.  The
 * deterministic helpers remain implementation details used by the scorer
 * definitions; callers must use this function for publication evidence.
 */
export async function runPhase10MastraScorers(target: Phase10EvalTarget) {
  const detailed = await runPhase10MastraScorersDetailed(target);
  return Object.freeze(
    Object.fromEntries(
      detailed.map((entry) => [entry.evalId, entry.officialScore]),
    ) as Record<keyof typeof phase10MastraScorers, number>,
  );
}

/** A published case is one official invocation of every registered scorer. */
export async function runPhase10MastraScorersDetailed(
  target: Phase10EvalTarget,
): Promise<
  readonly Readonly<{
    evalId: keyof typeof phase10MastraScorers;
    officialScore: number;
    score: Phase10Score;
  }>[]
> {
  const entries = Object.entries(phase10MastraScorers) as readonly (readonly [
    string,
    (typeof phase10MastraScorers)[keyof typeof phase10MastraScorers],
  ])[];
  const runs = await Promise.all(
    entries.map(async ([id, scorer]) => {
      const run = await scorer.run({ output: target });
      const resolver =
        targets[
          id
            .replace("phase10", "")
            .replace(/^./u, (value) =>
              value.toLowerCase(),
            ) as keyof typeof targets
        ];
      if (!resolver) throw new Error(`PHASE10_SCORER_RESOLVER_MISSING:${id}`);
      const score = resolver(target);
      if ((run.score === 1) !== score.passed)
        throw new Error(`PHASE10_OFFICIAL_SCORER_DIVERGENCE:${id}`);
      return {
        evalId: id as keyof typeof phase10MastraScorers,
        officialScore: run.score,
        score,
      };
    }),
  );
  return Object.freeze(runs);
}
