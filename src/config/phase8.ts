import { z } from "zod";

const optionalSecret = z.preprocess(
  (value) =>
    typeof value === "string" && value.trim().length === 0 ? undefined : value,
  z.string().trim().min(1).optional(),
);
const providerFlag = z
  .enum(["true", "false"])
  .default("false")
  .transform((value) => value === "true");
const csv = z.string().default("");
const incidentStatusKeys = [
  "received",
  "investigating",
  "awaiting_approval",
  "approved",
  "rejected",
  "containing",
  "contained",
  "failed",
  "closed",
] as const;
const exactPolicyInteger = (value: number) =>
  z.coerce
    .number()
    .int()
    .refine((input) => input === value, {
      message: `Must equal approved policy value ${value}.`,
    });

const phase8EnvironmentSchema = z.object({
  DEMO_MODE: z.enum(["mock", "staging", "production"]).default("mock"),
  WEBHOOKS_ENABLED: providerFlag.default(true),
  WORKOS_API_KEY: optionalSecret,
  WORKOS_PROVIDER_ENABLED: providerFlag,
  WORKOS_WEBHOOK_SECRET: optionalSecret,
  WORKOS_WEBHOOK_PREVIOUS_SECRET: optionalSecret,
  WORKOS_STAGING_ORGANIZATION_ID: z.string().trim().default(""),
  WORKOS_STAGING_ALLOWED_USER_IDS: csv,
  WORKOS_STAGING_ALLOWED_ROLE_SLUGS: csv,
  IPINFO_PROVIDER_ENABLED: providerFlag,
  IPINFO_TOKEN: optionalSecret,
  GEOIP_CACHE_HMAC_KEY: optionalSecret,
  GEOIP_CACHE_HMAC_KEY_VERSION: z.string().trim().optional(),
  GEOIP_CACHE_HMAC_PREVIOUS_KEY: optionalSecret,
  GEOIP_CACHE_HMAC_PREVIOUS_KEY_VERSION: z.string().trim().optional(),
  IPINFO_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(100)
    .max(10_000)
    .default(1_500),
  IPINFO_CACHE_TTL_SECONDS: exactPolicyInteger(86_400).default(86_400),
  IPINFO_EVIDENCE_RETENTION_DAYS: exactPolicyInteger(30).default(30),
  IPINFO_CONFIDENCE: z.coerce
    .number()
    .refine((input) => input === 0.7, {
      message: "Must equal approved policy value 0.70.",
    })
    .default(0.7),
  LINEAR_PROVIDER_ENABLED: providerFlag,
  LINEAR_API_KEY: optionalSecret,
  LINEAR_WORKSPACE_ID: z.string().trim().default(""),
  LINEAR_TEAM_ID: z.string().trim().default(""),
  LINEAR_PROJECT_ID: z.string().trim().default(""),
  LINEAR_SEVERITY_LABEL_IDS_JSON: z.string().trim().default(""),
  LINEAR_STATUS_STATE_IDS_JSON: z.string().trim().default(""),
  LINEAR_INTERNAL_BASE_URL: z.string().trim().default(""),
  UPSTASH_PUBSUB_ENABLED: providerFlag,
  UPSTASH_REDIS_URL: z.string().trim().default(""),
  UPSTASH_REDIS_KEY_PREFIX: z.string().trim().default("mastra:security:v1"),
  UPSTASH_WORKFLOW_CONSUMER_GROUP: z
    .string()
    .trim()
    .default("security-workflow-starters"),
  UPSTASH_CONSUMER_CONCURRENCY: exactPolicyInteger(4).default(4),
  UPSTASH_MAX_DELIVERY_ATTEMPTS: exactPolicyInteger(5).default(5),
  UPSTASH_RETRY_BACKOFF_MS: z.string().default("500,1000,2000,4000"),
  UPSTASH_RECLAIM_INTERVAL_MS: exactPolicyInteger(30_000).default(30_000),
  UPSTASH_RECLAIM_IDLE_MS: exactPolicyInteger(60_000).default(60_000),
  UPSTASH_STREAM_MAX_LENGTH: exactPolicyInteger(100_000).default(100_000),
  UPSTASH_STREAM_IDLE_TTL_MS: exactPolicyInteger(0).default(0),
});

export type Phase8Config = Readonly<{
  mode: "mock" | "staging" | "production";
  workos: Readonly<{
    enabled: boolean;
    apiKey?: string;
    webhookSecret?: string;
    previousWebhookSecret?: string;
    organizationId?: string;
    allowedUserIds: ReadonlySet<string>;
    allowedRoleSlugs: ReadonlySet<string>;
  }>;
  ipinfo: Readonly<{
    enabled: boolean;
    token?: string;
    /** Canonical, decoded HMAC key material. Never log or persist this. */
    cacheHmacKey?: Uint8Array;
    /** Stable label persisted beside entries written with the current key. */
    cacheHmacKeyVersion?: string;
    /** Optional prior key used only for cache read-through during rotation. */
    previousCacheHmacKey?: Uint8Array;
    /** Required exactly when the previous key is configured. */
    previousCacheHmacKeyVersion?: string;
    timeoutMs: number;
    cacheTtlSeconds: 86400;
    evidenceRetentionDays: 30;
    confidence: 0.7;
  }>;
  linear: Readonly<{
    enabled: boolean;
    apiKey?: string;
    workspaceId?: string;
    teamId?: string;
    projectId?: string;
    severityLabelIds?: Readonly<
      Record<"low" | "medium" | "high" | "critical", string>
    >;
    statusStateIds?: Readonly<Record<string, string>>;
    internalBaseUrl?: string;
  }>;
  upstash: Readonly<{
    enabled: boolean;
    redisUrl?: string;
    keyPrefix: "mastra:security:v1";
    workflowConsumerGroup: "security-workflow-starters";
    concurrency: number;
    maxDeliveryAttempts: 5;
    retryBackoffMs: readonly [500, 1000, 2000, 4000];
    reclaimIntervalMs: 30000;
    reclaimIdleMs: 60000;
    maxStreamLength: 100000;
    streamIdleTtlMs: 0;
  }>;
}>;

/** A real provider turns the Mastra control plane into production surface. */
export function hasRealPhase8Provider(config: Phase8Config): boolean {
  return (
    config.workos.enabled ||
    config.ipinfo.enabled ||
    config.linear.enabled ||
    config.upstash.enabled
  );
}

/**
 * Keep this check separate from the dashboard UI flag.  UI enablement is a
 * presentation choice; the server/runtime control plane is never public when
 * any real adapter is present.
 */
export function assertPhase8ControlPlaneAuth(
  config: Phase8Config,
  environment: NodeJS.ProcessEnv = process.env,
): void {
  if (!hasRealPhase8Provider(config)) return;
  if (
    !environment.WORKOS_API_KEY ||
    !environment.WORKOS_CLIENT_ID ||
    !environment.WORKOS_REDIRECT_URI ||
    !environment.WORKOS_COOKIE_PASSWORD
  )
    throw new Error(
      "Real providers require WorkOS server/runtime control-plane authentication.",
    );
}

function isPlaceholder(value: string): boolean {
  return value.length === 0 || /<[^>]+>/u.test(value);
}

/** Provider credentials are never accepted as short placeholder-like values. */
function hasMinimumSecretLength(value: string | undefined): boolean {
  return typeof value === "string" && value.length >= 16;
}

function readCsv(value: string, name: string): ReadonlySet<string> {
  const entries = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (entries.some(isPlaceholder) || new Set(entries).size !== entries.length)
    throw new Error(`Invalid ${name}.`);
  return new Set(entries);
}

function parseIdMap(
  value: string,
  name: string,
  exactKeys?: readonly string[],
) {
  if (isPlaceholder(value)) throw new Error(`Invalid ${name}.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`Invalid ${name}.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new Error(`Invalid ${name}.`);
  const record = parsed as Record<string, unknown>;
  if (
    exactKeys &&
    (Object.keys(record).length !== exactKeys.length ||
      exactKeys.some(
        (key) =>
          typeof record[key] !== "string" ||
          isPlaceholder(record[key] as string),
      ))
  )
    throw new Error(`Invalid ${name}.`);
  if (
    !exactKeys &&
    Object.values(record).some(
      (item) => typeof item !== "string" || isPlaceholder(item),
    )
  )
    throw new Error(`Invalid ${name}.`);
  return Object.freeze(record as Record<string, string>);
}

/**
 * Cache keys are deliberately encoded rather than accepted as arbitrary text:
 * this makes an accidental short password or an unmarked encoding fail at
 * process start.  The prefix also keeps a hex key from being mistaken for
 * base64 during a rotation.
 */
function readGeoIpCacheHmacKey(value: string | undefined, name: string) {
  if (!value || isPlaceholder(value)) throw new Error(`Invalid ${name}.`);
  const match = /^(hex|base64):(.+)$/u.exec(value);
  if (!match) throw new Error(`Invalid ${name}.`);
  const encoding = match[1] as "hex" | "base64";
  const encoded = match[2] as string;
  if (
    (encoding === "hex" &&
      (!/^[0-9a-fA-F]+$/u.test(encoded) || encoded.length % 2 !== 0)) ||
    (encoding === "base64" &&
      (!/^[A-Za-z0-9+/]*={0,2}$/u.test(encoded) || encoded.length % 4 !== 0))
  )
    throw new Error(`Invalid ${name}.`);
  const decoded = Buffer.from(encoded, encoding);
  // Reject non-canonical base64 (for example, silently ignored whitespace).
  if (
    decoded.length < 32 ||
    (encoding === "hex"
      ? decoded.toString("hex").toLowerCase() !== encoded.toLowerCase()
      : decoded.toString("base64") !== encoded)
  )
    throw new Error(`Invalid ${name}.`);
  return new Uint8Array(decoded);
}

function readGeoIpCacheHmacKeyVersion(
  value: string | undefined,
  name: string,
): string {
  if (
    !value ||
    isPlaceholder(value) ||
    !/^[a-z][a-z0-9._-]{0,63}$/u.test(value)
  )
    throw new Error(`Invalid ${name}.`);
  return value;
}

/** Real providers are opt-in, staging-only, and reject placeholder configuration. */
export function readPhase8Config(
  environment: NodeJS.ProcessEnv = process.env,
): Phase8Config {
  const parsed = phase8EnvironmentSchema.safeParse(environment);
  if (!parsed.success) throw new Error("Invalid Phase 8 configuration.");
  const value = parsed.data;
  if (value.DEMO_MODE === "production")
    throw new Error("Production mode is blocked.");
  const anyReal =
    value.WORKOS_PROVIDER_ENABLED ||
    value.IPINFO_PROVIDER_ENABLED ||
    value.LINEAR_PROVIDER_ENABLED ||
    value.UPSTASH_PUBSUB_ENABLED;
  if (anyReal && value.DEMO_MODE !== "staging")
    throw new Error("Real providers require staging mode.");
  const workosUsers = value.WORKOS_PROVIDER_ENABLED
    ? readCsv(
        value.WORKOS_STAGING_ALLOWED_USER_IDS,
        "WORKOS_STAGING_ALLOWED_USER_IDS",
      )
    : new Set<string>();
  const workosRoles = value.WORKOS_PROVIDER_ENABLED
    ? readCsv(
        value.WORKOS_STAGING_ALLOWED_ROLE_SLUGS,
        "WORKOS_STAGING_ALLOWED_ROLE_SLUGS",
      )
    : new Set<string>();
  if (
    value.WORKOS_PROVIDER_ENABLED &&
    (!value.WEBHOOKS_ENABLED ||
      !hasMinimumSecretLength(value.WORKOS_API_KEY) ||
      !hasMinimumSecretLength(value.WORKOS_WEBHOOK_SECRET) ||
      isPlaceholder(value.WORKOS_STAGING_ORGANIZATION_ID) ||
      workosUsers.size === 0 ||
      workosRoles.size === 0 ||
      value.WORKOS_WEBHOOK_SECRET === value.WORKOS_WEBHOOK_PREVIOUS_SECRET)
  )
    throw new Error("WorkOS provider configuration is incomplete.");
  if (
    value.IPINFO_PROVIDER_ENABLED &&
    (!hasMinimumSecretLength(value.IPINFO_TOKEN) ||
      !value.GEOIP_CACHE_HMAC_KEY ||
      !value.GEOIP_CACHE_HMAC_KEY_VERSION)
  )
    throw new Error("IPinfo provider configuration is incomplete.");
  const cacheHmacKey = value.IPINFO_PROVIDER_ENABLED
    ? readGeoIpCacheHmacKey(value.GEOIP_CACHE_HMAC_KEY, "GEOIP_CACHE_HMAC_KEY")
    : undefined;
  const cacheHmacKeyVersion = value.IPINFO_PROVIDER_ENABLED
    ? readGeoIpCacheHmacKeyVersion(
        value.GEOIP_CACHE_HMAC_KEY_VERSION,
        "GEOIP_CACHE_HMAC_KEY_VERSION",
      )
    : undefined;
  if (
    value.IPINFO_PROVIDER_ENABLED &&
    Boolean(value.GEOIP_CACHE_HMAC_PREVIOUS_KEY) !==
      Boolean(value.GEOIP_CACHE_HMAC_PREVIOUS_KEY_VERSION)
  )
    throw new Error("IPinfo provider configuration is incomplete.");
  const previousCacheHmacKey =
    value.IPINFO_PROVIDER_ENABLED && value.GEOIP_CACHE_HMAC_PREVIOUS_KEY
      ? readGeoIpCacheHmacKey(
          value.GEOIP_CACHE_HMAC_PREVIOUS_KEY,
          "GEOIP_CACHE_HMAC_PREVIOUS_KEY",
        )
      : undefined;
  const previousCacheHmacKeyVersion =
    value.IPINFO_PROVIDER_ENABLED && value.GEOIP_CACHE_HMAC_PREVIOUS_KEY_VERSION
      ? readGeoIpCacheHmacKeyVersion(
          value.GEOIP_CACHE_HMAC_PREVIOUS_KEY_VERSION,
          "GEOIP_CACHE_HMAC_PREVIOUS_KEY_VERSION",
        )
      : undefined;
  if (
    value.IPINFO_PROVIDER_ENABLED &&
    previousCacheHmacKey &&
    cacheHmacKey &&
    (Buffer.from(previousCacheHmacKey).equals(Buffer.from(cacheHmacKey)) ||
      previousCacheHmacKeyVersion === cacheHmacKeyVersion)
  )
    throw new Error("IPinfo provider configuration is incomplete.");
  const severityLabelIds = value.LINEAR_PROVIDER_ENABLED
    ? (parseIdMap(
        value.LINEAR_SEVERITY_LABEL_IDS_JSON,
        "LINEAR_SEVERITY_LABEL_IDS_JSON",
        ["low", "medium", "high", "critical"],
      ) as Readonly<Record<"low" | "medium" | "high" | "critical", string>>)
    : undefined;
  const statusStateIds = value.LINEAR_PROVIDER_ENABLED
    ? parseIdMap(
        value.LINEAR_STATUS_STATE_IDS_JSON,
        "LINEAR_STATUS_STATE_IDS_JSON",
        incidentStatusKeys,
      )
    : undefined;
  if (
    value.LINEAR_PROVIDER_ENABLED &&
    (!hasMinimumSecretLength(value.LINEAR_API_KEY) ||
      isPlaceholder(value.LINEAR_WORKSPACE_ID) ||
      isPlaceholder(value.LINEAR_TEAM_ID) ||
      isPlaceholder(value.LINEAR_INTERNAL_BASE_URL))
  )
    throw new Error("Linear provider configuration is incomplete.");
  if (value.LINEAR_PROVIDER_ENABLED) {
    const url = new URL(value.LINEAR_INTERNAL_BASE_URL);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error(
        "LINEAR_INTERNAL_BASE_URL must be an allowlisted HTTPS base URL.",
      );
  }
  if (
    value.UPSTASH_PUBSUB_ENABLED &&
    (!/^rediss:\/\//u.test(value.UPSTASH_REDIS_URL) ||
      value.UPSTASH_REDIS_KEY_PREFIX !== "mastra:security:v1" ||
      value.UPSTASH_WORKFLOW_CONSUMER_GROUP !== "security-workflow-starters" ||
      value.UPSTASH_RETRY_BACKOFF_MS !== "500,1000,2000,4000")
  )
    throw new Error("Upstash provider configuration is incomplete.");
  return Object.freeze({
    mode: value.DEMO_MODE,
    workos: Object.freeze({
      enabled: value.WORKOS_PROVIDER_ENABLED,
      ...(value.WORKOS_API_KEY ? { apiKey: value.WORKOS_API_KEY } : {}),
      ...(value.WORKOS_WEBHOOK_SECRET
        ? { webhookSecret: value.WORKOS_WEBHOOK_SECRET }
        : {}),
      ...(value.WORKOS_WEBHOOK_PREVIOUS_SECRET
        ? { previousWebhookSecret: value.WORKOS_WEBHOOK_PREVIOUS_SECRET }
        : {}),
      ...(!isPlaceholder(value.WORKOS_STAGING_ORGANIZATION_ID)
        ? { organizationId: value.WORKOS_STAGING_ORGANIZATION_ID }
        : {}),
      allowedUserIds: workosUsers,
      allowedRoleSlugs: workosRoles,
    }),
    ipinfo: Object.freeze({
      enabled: value.IPINFO_PROVIDER_ENABLED,
      ...(value.IPINFO_TOKEN ? { token: value.IPINFO_TOKEN } : {}),
      ...(cacheHmacKey ? { cacheHmacKey } : {}),
      ...(cacheHmacKeyVersion ? { cacheHmacKeyVersion } : {}),
      ...(previousCacheHmacKey ? { previousCacheHmacKey } : {}),
      ...(previousCacheHmacKeyVersion ? { previousCacheHmacKeyVersion } : {}),
      timeoutMs: value.IPINFO_TIMEOUT_MS,
      cacheTtlSeconds: 86400,
      evidenceRetentionDays: 30,
      confidence: 0.7,
    }),
    linear: Object.freeze({
      enabled: value.LINEAR_PROVIDER_ENABLED,
      ...(value.LINEAR_API_KEY ? { apiKey: value.LINEAR_API_KEY } : {}),
      ...(!isPlaceholder(value.LINEAR_WORKSPACE_ID)
        ? { workspaceId: value.LINEAR_WORKSPACE_ID }
        : {}),
      ...(!isPlaceholder(value.LINEAR_TEAM_ID)
        ? { teamId: value.LINEAR_TEAM_ID }
        : {}),
      ...(!isPlaceholder(value.LINEAR_PROJECT_ID)
        ? { projectId: value.LINEAR_PROJECT_ID }
        : {}),
      ...(severityLabelIds ? { severityLabelIds } : {}),
      ...(statusStateIds ? { statusStateIds } : {}),
      ...(!isPlaceholder(value.LINEAR_INTERNAL_BASE_URL)
        ? { internalBaseUrl: value.LINEAR_INTERNAL_BASE_URL }
        : {}),
    }),
    upstash: Object.freeze({
      enabled: value.UPSTASH_PUBSUB_ENABLED,
      ...(value.UPSTASH_REDIS_URL ? { redisUrl: value.UPSTASH_REDIS_URL } : {}),
      keyPrefix: "mastra:security:v1",
      workflowConsumerGroup: "security-workflow-starters",
      concurrency: value.UPSTASH_CONSUMER_CONCURRENCY,
      maxDeliveryAttempts: 5,
      retryBackoffMs: [500, 1000, 2000, 4000] as const,
      reclaimIntervalMs: 30000,
      reclaimIdleMs: 60000,
      maxStreamLength: 100000,
      streamIdleTtlMs: 0,
    }),
  });
}
