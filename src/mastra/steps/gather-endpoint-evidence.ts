import { MockEndpointEvidenceProvider } from "../../providers/endpoint-evidence-provider.js";
import type { EndpointEvidenceProvider } from "../../providers/evidence-provider.js";
import { invokeEndpointInvestigator } from "../agents/endpoint-investigator.js";
import { createEvidenceReadTool } from "../tools/evidence-read-tool.js";
import {
  createGatherEvidenceStep,
  type GatherDependencies,
} from "./gather-evidence.js";

export function createGatherEndpointEvidenceStep(
  dependencies: Omit<
    GatherDependencies<"endpoint">,
    "tool" | "investigator"
  > & {
    provider?: EndpointEvidenceProvider;
    tool?: GatherDependencies<"endpoint">["tool"];
    investigator?: GatherDependencies<"endpoint">["investigator"];
  } = {},
) {
  const provider =
    dependencies.provider ??
    new MockEndpointEvidenceProvider({
      // The default in-process workflow is a fixture harness, not a device
      // verifier. Making this authority explicit keeps direct provider use
      // fail-closed while preserving the established mock workflow contract.
      verifyDeviceSignature: (input) => input.deviceId === "device-new-1",
    });
  return createGatherEvidenceStep("endpoint", {
    ...dependencies,
    tool:
      dependencies.tool ??
      createEvidenceReadTool({
        id: "endpoint-read-tool",
        source: "endpoint",
        description: "Read endpoint evidence within the trusted scope.",
        provider,
        timeoutMs: dependencies.timeoutMs ?? 1_500,
      }),
    investigator: dependencies.investigator ?? invokeEndpointInvestigator,
  });
}
