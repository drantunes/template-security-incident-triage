import { MockIdentityEvidenceProvider } from "../../providers/identity-evidence-provider.js";
import { createEvidenceReadTool } from "./evidence-read-tool.js";

export const identityReadTool = createEvidenceReadTool({
  id: "identity-read-tool",
  source: "identity",
  description:
    "Read synthetic identity evidence for the trusted investigation scope.",
  provider: new MockIdentityEvidenceProvider(),
  timeoutMs: 1_500,
});
