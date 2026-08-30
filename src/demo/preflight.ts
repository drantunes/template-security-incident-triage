import type { DemoMode, DemoPreflight, DemoScenario } from "./contracts.js";
import { readPhase8Config } from "../env.js";

export function preflightDemo(
  input: Readonly<{
    mode: DemoMode;
    real?: boolean;
    confirmed?: boolean;
    scenario?: DemoScenario;
    environment?: NodeJS.ProcessEnv;
  }>,
): DemoPreflight {
  if (input.mode === "production") {
    return {
      ok: false,
      code: "DEMO_PRODUCTION_BLOCKED",
      mode: input.mode,
      capabilities: {},
      operations: [],
    };
  }
  if (input.mode === "mock") {
    if (input.real || input.confirmed) {
      return {
        ok: false,
        code: "DEMO_MOCK_CONSENT_FLAGS_INVALID",
        mode: input.mode,
        capabilities: { network: "blocked" },
        operations: [],
      };
    }
    return {
      ok: true,
      mode: input.mode,
      capabilities: {
        workflow: "supported",
        approval: "supported",
        restore_previous_role: "supported",
        revoke_session: "supported",
        require_reauthentication: "supported",
        mark_device_for_review: "supported",
        network: "blocked",
      },
      operations: [
        "local LibSQL",
        "in-process signed webhook",
        "mock containment only",
      ],
    };
  }
  const environment = input.environment ?? process.env;
  // Reuse the strict F8 parser rather than duplicating an increasingly stale
  // approximation of provider configuration. A semantic demo target must also
  // bind to the exact WorkOS user and role allowlists; present configuration is
  // still not authorization and this code never opens a network connection.
  let configured: boolean;
  try {
    const config = readPhase8Config(environment);
    const targetUserId = environment.DEMO_STAGING_TARGET_USER_ID;
    const targetRole = environment.DEMO_STAGING_TARGET_ROLE;
    const targetOrganizationId =
      environment.DEMO_STAGING_TARGET_ORGANIZATION_ID;
    const targetSessionId = environment.DEMO_STAGING_TARGET_SESSION_ID;
    const targetDeviceId = environment.DEMO_STAGING_TARGET_DEVICE_ID;
    const operation = environment.DEMO_STAGING_OPERATION;
    const scenarioActions: Readonly<Record<DemoScenario, readonly string[]>> = {
      privilege: ["restore_previous_role", "revoke_session"],
      country: ["revoke_session", "require_reauthentication"],
      device: ["revoke_session", "mark_device_for_review"],
    };
    const supportedOperations = new Set([
      "restore_previous_role",
      "revoke_session",
    ]);
    const opaqueTarget = (value: string | undefined) =>
      typeof value === "string" &&
      /^[a-z][a-z0-9._-]{0,127}$/u.test(value) &&
      !/(?:fake|placeholder|example|invalid)/iu.test(value);
    const allowed = (value: string | undefined, name: string) => {
      if (!opaqueTarget(value)) return false;
      const entries = (environment[name] ?? "")
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean);
      return (
        entries.length > 0 &&
        new Set(entries).size === entries.length &&
        entries.includes(value!)
      );
    };
    const actions = input.scenario ? scenarioActions[input.scenario] : [];
    const allActionsSupported = actions.every((action) =>
      supportedOperations.has(action),
    );
    configured =
      input.real === true &&
      input.confirmed === true &&
      config.mode === "staging" &&
      config.workos.enabled &&
      config.ipinfo.enabled &&
      config.linear.enabled &&
      config.upstash.enabled &&
      typeof config.linear.projectId === "string" &&
      config.linear.projectId.length > 0 &&
      opaqueTarget(targetOrganizationId) &&
      targetOrganizationId === config.workos.organizationId &&
      opaqueTarget(targetUserId) &&
      opaqueTarget(targetRole) &&
      config.workos.allowedUserIds.has(targetUserId ?? "") &&
      config.workos.allowedRoleSlugs.has(targetRole ?? "") &&
      input.scenario !== undefined &&
      typeof operation === "string" &&
      actions.includes(operation) &&
      supportedOperations.has(operation) &&
      allActionsSupported &&
      // Targets are validated by every action in the selected plan, never by
      // a convenient scenario shortcut. In particular device + revoke_session
      // needs both the allowlisted device and its explicit session target.
      (!actions.includes("revoke_session") ||
        allowed(targetSessionId, "DEMO_STAGING_ALLOWED_SESSION_IDS")) &&
      (!actions.includes("mark_device_for_review") ||
        allowed(targetDeviceId, "DEMO_STAGING_ALLOWED_DEVICE_IDS"));
  } catch {
    configured = false;
  }
  return {
    ok: configured,
    ...(configured ? {} : { code: "DEMO_STAGING_PRECONDITION_FAILED" }),
    mode: input.mode,
    capabilities: {
      restore_previous_role: "supported",
      revoke_session: "supported",
      require_reauthentication: "unsupported",
      mark_device_for_review: "unsupported",
      network: "blocked",
    },
    operations: [
      "hermetic preflight only",
      "no provider request",
      "no containment",
    ],
  };
}
