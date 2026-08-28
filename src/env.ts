import { z } from "zod";

const integer = (fallback: number, minimum: number, maximum: number) =>
  z.coerce.number().int().min(minimum).max(maximum).default(fallback);

const environmentSchema = z.object({
  DEMO_MODE: z.literal("mock").default("mock"),
  WEBHOOKS_ENABLED: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  ALERT_WEBHOOK_SECRET: z.string().min(16).optional(),
  WORKOS_WEBHOOK_SECRET: z.string().min(16).optional(),
  ALERT_WEBHOOK_SOURCES: z.string().default("demo"),
  WEBHOOK_MAX_BODY_BYTES: integer(65_536, 1_024, 262_144),
  MASTRA_MAX_BODY_BYTES: integer(1_048_576, 65_536, 4_194_304),
  OUTBOX_POLL_INTERVAL_MS: integer(250, 25, 60_000),
  OUTBOX_BATCH_SIZE: integer(16, 1, 100),
  OUTBOX_LEASE_MS: integer(10_000, 1_000, 300_000),
  OUTBOX_MAX_ATTEMPTS: integer(5, 1, 20),
  OUTBOX_BACKOFF_BASE_MS: integer(500, 10, 60_000),
  OUTBOX_BACKOFF_CAP_MS: integer(30_000, 100, 600_000),
  OUTBOX_RECOVERY_GRACE_MS: integer(10_000, 1_000, 600_000),
  PORT: integer(3_000, 1, 65_535),
});

export type Phase2Config = Readonly<{
  mode: "mock";
  webhooksEnabled: boolean;
  alertWebhookSecret?: string;
  workosWebhookSecret?: string;
  alertWebhookSources: ReadonlySet<string>;
  webhookMaxBodyBytes: number;
  mastraMaxBodyBytes: number;
  outbox: Readonly<{
    pollIntervalMs: number;
    batchSize: number;
    leaseMs: number;
    maxAttempts: number;
    backoffBaseMs: number;
    backoffCapMs: number;
    recoveryGraceMs: number;
  }>;
  port: number;
}>;

export function readPhase2Config(
  environment: NodeJS.ProcessEnv = process.env,
): Phase2Config {
  const parsed = environmentSchema.safeParse(environment);
  if (!parsed.success) throw new Error("Invalid Phase 2 configuration.");
  const value = parsed.data;
  if (
    value.WEBHOOKS_ENABLED &&
    (!value.ALERT_WEBHOOK_SECRET || !value.WORKOS_WEBHOOK_SECRET)
  ) {
    throw new Error(
      "ALERT_WEBHOOK_SECRET and WORKOS_WEBHOOK_SECRET are required when webhooks are enabled.",
    );
  }
  const sources = new Set(
    value.ALERT_WEBHOOK_SOURCES.split(",")
      .map((source) => source.trim())
      .filter((source) => /^[a-z0-9][a-z0-9._-]{0,63}$/u.test(source)),
  );
  if (sources.size === 0) throw new Error("No valid alert source configured.");
  return Object.freeze({
    mode: value.DEMO_MODE,
    webhooksEnabled: value.WEBHOOKS_ENABLED,
    ...(value.ALERT_WEBHOOK_SECRET
      ? { alertWebhookSecret: value.ALERT_WEBHOOK_SECRET }
      : {}),
    ...(value.WORKOS_WEBHOOK_SECRET
      ? { workosWebhookSecret: value.WORKOS_WEBHOOK_SECRET }
      : {}),
    alertWebhookSources: sources,
    webhookMaxBodyBytes: value.WEBHOOK_MAX_BODY_BYTES,
    mastraMaxBodyBytes: value.MASTRA_MAX_BODY_BYTES,
    outbox: Object.freeze({
      pollIntervalMs: value.OUTBOX_POLL_INTERVAL_MS,
      batchSize: value.OUTBOX_BATCH_SIZE,
      leaseMs: value.OUTBOX_LEASE_MS,
      maxAttempts: value.OUTBOX_MAX_ATTEMPTS,
      backoffBaseMs: value.OUTBOX_BACKOFF_BASE_MS,
      backoffCapMs: value.OUTBOX_BACKOFF_CAP_MS,
      recoveryGraceMs: value.OUTBOX_RECOVERY_GRACE_MS,
    }),
    port: value.PORT,
  });
}

const phase4EnvironmentSchema = z.object({
  MASTRA_MODEL: z.string().trim().min(1).default("openai/gpt-4o-mini"),
  EVIDENCE_IDENTITY_TIMEOUT_MS: integer(1_500, 100, 30_000),
  EVIDENCE_ENDPOINT_TIMEOUT_MS: integer(1_500, 100, 30_000),
  EVIDENCE_CLOUD_TIMEOUT_MS: integer(1_500, 100, 30_000),
});

export type Phase4Config = Readonly<{
  model: string;
  timeouts: Readonly<Record<"identity" | "endpoint" | "cloud", number>>;
}>;

export function readPhase4Config(
  environment: NodeJS.ProcessEnv = process.env,
): Phase4Config {
  const parsed = phase4EnvironmentSchema.safeParse(environment);
  if (!parsed.success) throw new Error("Invalid Phase 4 configuration.");
  return Object.freeze({
    model: parsed.data.MASTRA_MODEL,
    timeouts: Object.freeze({
      identity: parsed.data.EVIDENCE_IDENTITY_TIMEOUT_MS,
      endpoint: parsed.data.EVIDENCE_ENDPOINT_TIMEOUT_MS,
      cloud: parsed.data.EVIDENCE_CLOUD_TIMEOUT_MS,
    }),
  });
}

const phase6EnvironmentSchema = z.object({
  DEMO_MODE: z.enum(["mock", "staging", "production"]).default("mock"),
  MOCK_DECISIONS_ENABLED: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
  MOCK_DECISION_SECRET: z.string().min(32).optional(),
  APPROVAL_RESUME_SECRET: z.string().min(32).optional(),
  CONTAINMENT_ACTION_TIMEOUT_MS: integer(1_000, 100, 10_000),
  CONTAINMENT_RATE_LIMIT: integer(8, 1, 32),
});

export type Phase6Config = Readonly<{
  mode: "mock" | "staging" | "production";
  mockDecisionsEnabled: boolean;
  mockDecisionSecret?: string;
  approvalResumeSecret?: string;
  actionTimeoutMs: number;
  rateLimit: number;
}>;

export function readPhase6Config(
  environment: NodeJS.ProcessEnv = process.env,
): Phase6Config {
  const parsed = phase6EnvironmentSchema.safeParse(environment);
  if (!parsed.success) throw new Error("Invalid Phase 6 configuration.");
  const value = parsed.data;
  if (
    value.MOCK_DECISIONS_ENABLED &&
    (value.DEMO_MODE !== "mock" ||
      !value.MOCK_DECISION_SECRET ||
      !value.APPROVAL_RESUME_SECRET)
  ) {
    throw new Error(
      "Mock decisions require mock mode and dedicated decision/resume secrets.",
    );
  }
  return Object.freeze({
    mode: value.DEMO_MODE,
    mockDecisionsEnabled: value.MOCK_DECISIONS_ENABLED,
    ...(value.MOCK_DECISION_SECRET
      ? { mockDecisionSecret: value.MOCK_DECISION_SECRET }
      : {}),
    ...(value.APPROVAL_RESUME_SECRET
      ? { approvalResumeSecret: value.APPROVAL_RESUME_SECRET }
      : {}),
    actionTimeoutMs: value.CONTAINMENT_ACTION_TIMEOUT_MS,
    rateLimit: value.CONTAINMENT_RATE_LIMIT,
  });
}
