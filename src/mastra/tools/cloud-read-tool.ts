import { MockCloudEvidenceProvider } from "../../providers/cloud-evidence-provider.js";
import { createEvidenceReadTool } from "./evidence-read-tool.js";

export const cloudReadTool = createEvidenceReadTool({
  id: "cloud-read-tool",
  source: "cloud",
  description:
    "Read synthetic cloud evidence for the trusted investigation scope.",
  provider: new MockCloudEvidenceProvider(),
  timeoutMs: 1_500,
});
