import { MockEndpointEvidenceProvider } from "../../providers/endpoint-evidence-provider.js";
import { createEvidenceReadTool } from "./evidence-read-tool.js";

export const endpointReadTool = createEvidenceReadTool({
  id: "endpoint-read-tool",
  source: "endpoint",
  description:
    "Read synthetic endpoint evidence for the trusted investigation scope.",
  provider: new MockEndpointEvidenceProvider(),
  timeoutMs: 1_500,
});
