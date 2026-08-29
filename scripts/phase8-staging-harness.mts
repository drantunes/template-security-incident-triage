import { readPhase8Config } from "../src/env.js";
import {
  createDryRunPhase8SmokeBoundaries,
  createRealPhase8SmokeBoundaries,
  phase8SmokeProviders,
  runPhase8Smoke,
  type Phase8SmokeProvider,
} from "../src/staging/phase8-smoke.js";

const provider = process.argv[2];
const confirm = process.env.PHASE8_STAGING_CONFIRM;
const cleanup = process.argv.includes("--cleanup");
const dryRun = !process.argv.includes("--real");

if (!phase8SmokeProviders.includes(provider as Phase8SmokeProvider)) {
  throw new Error("Choose one provider: workos, ipinfo, linear, upstash.");
}
if (confirm !== "PHASE8_HERMETIC_CHECK") {
  throw new Error("Set PHASE8_STAGING_CONFIRM=PHASE8_HERMETIC_CHECK.");
}
if (
  cleanup &&
  process.env.PHASE8_STAGING_CLEANUP_CONFIRM !== "PHASE8_CLEANUP_ONLY"
) {
  throw new Error(
    "Cleanup requires PHASE8_STAGING_CLEANUP_CONFIRM=PHASE8_CLEANUP_ONLY.",
  );
}
if (!dryRun && process.env.PHASE8_REAL_CONFIRM !== "PHASE8_REAL_SMOKE")
  throw new Error("Real mode requires PHASE8_REAL_CONFIRM=PHASE8_REAL_SMOKE.");

const selected = provider as "workos" | "ipinfo" | "linear" | "upstash";
const config = readPhase8Config(process.env);
if (config.mode !== "staging" || !config[selected].enabled) {
  throw new Error(`Staging flag for ${provider} is required.`);
}

console.log(
  JSON.stringify(
    await runPhase8Smoke({
      provider: selected,
      config,
      real: !dryRun,
      cleanup,
      boundaries: dryRun
        ? createDryRunPhase8SmokeBoundaries()
        : createRealPhase8SmokeBoundaries(),
    }),
  ),
);
