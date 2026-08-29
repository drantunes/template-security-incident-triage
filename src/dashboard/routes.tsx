/** @jsxImportSource hono/jsx */
import type { Context, Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { bodyLimit } from "hono/body-limit";

import {
  createCsrfToken,
  isSameOriginMutation,
  verifyCsrfToken,
} from "../auth/csrf.js";
import {
  resolveDashboardPrincipal,
  type DashboardPrincipal,
} from "../auth/dashboard-principal.js";
import {
  openPkceState,
  safeDashboardNext,
  sealPkceState,
} from "../auth/pkce-state.js";
import {
  safeWorkosRedirect,
  type DashboardSessionClient,
} from "../auth/workos-session.js";
import {
  openSessionIssuedAt,
  sealSessionIssuedAt,
} from "../auth/session-lifetime.js";
import type { ReconcileApprovalRun } from "../approval/workflow-resume-reconciler.js";
import type { OperationalStore } from "../db/operational-store.js";
import { DomainError } from "../domain/errors.js";
import type { Phase6Config, Phase7Config } from "../env.js";
import type { AppEnv } from "../http-context.js";
import type { StructuredLogger } from "../logging.js";
import {
  DashboardDecisionRequestSchema,
  IncidentListQuerySchema,
} from "./contracts.js";
import { decideDashboardApproval } from "./approval.js";
import { dashboardCss, dashboardJs } from "./assets.js";
import { listDashboardIncidents, readDashboardIncident } from "./queries.js";
import { sseResyncResponse, sseResponse, validateSseReplay } from "./sse.js";
import {
  DashboardShell,
  DashboardUnavailable,
  IncidentDetail,
  LoginPage,
  OrganizationPicker,
} from "./views.js";

const sessionCookie = "__Host-authkit-session";
const stateCookie = "__Host-authkit-pkce";
const issuedCookie = "__Host-authkit-issued-at";
const defaultAuthMutationMaxBodyBytes = 1_048_576;
type DashboardDependencies = Readonly<{
  store: OperationalStore;
  logger: StructuredLogger;
  config: Phase7Config;
  phase6Config: Phase6Config;
  sessionClient: DashboardSessionClient | null;
  reconcileApprovalRun: ReconcileApprovalRun;
  authMutationMaxBodyBytes?: number;
  nowMs?: () => number;
}>;

export function registerDashboardRoutes(
  app: Hono<AppEnv>,
  dependencies: DashboardDependencies,
): void {
  const nowMs = dependencies.nowMs ?? Date.now;
  const authMutationBodyLimit = bodyLimit({
    maxSize:
      dependencies.authMutationMaxBodyBytes ?? defaultAuthMutationMaxBodyBytes,
    onError: (context) => dashboardError(context, "PAYLOAD_TOO_LARGE", 413),
  });
  const activeSse = new Map<string, number>();
  const rateWindows = new Map<string, { startedAt: number; count: number }>();
  const clientKey = (context: Context<AppEnv>) => {
    if (!dependencies.config.trustedProxy) return "direct";
    const forwarded = context.req
      .header("x-forwarded-for")
      ?.split(",")[0]
      ?.trim();
    return forwarded && /^[0-9a-f:.]{1,64}$/iu.test(forwarded)
      ? forwarded
      : "proxy-unknown";
  };
  const limited = (context: Context<AppEnv>, bucket: string, max: number) => {
    const client = clientKey(context);
    const key = `${bucket}:${client}`;
    const now = nowMs();
    for (const [candidate, value] of rateWindows)
      if (now - value.startedAt >= 60_000) rateWindows.delete(candidate);
    if (rateWindows.size >= 1024 && !rateWindows.has(key))
      rateWindows.delete(rateWindows.keys().next().value!);
    const window = rateWindows.get(key);
    if (!window || now - window.startedAt >= 60_000) {
      rateWindows.set(key, { startedAt: now, count: 1 });
      return false;
    }
    window.count += 1;
    if (window.count > max) {
      context.header(
        "Retry-After",
        String(Math.ceil((60_000 - (now - window.startedAt)) / 1000)),
      );
      return true;
    }
    return false;
  };
  app.get("/assets/dashboard.css", (context) => {
    // Stable URLs must revalidate; immutable caching is safe only for
    // content-addressed paths.
    context.header("Cache-Control", "public, max-age=0, must-revalidate");
    context.header("Content-Type", "text/css; charset=utf-8");
    return context.body(dashboardCss);
  });
  app.get("/assets/dashboard.js", (context) => {
    context.header("Cache-Control", "public, max-age=0, must-revalidate");
    context.header("Content-Type", "application/javascript; charset=utf-8");
    return context.body(dashboardJs);
  });
  app.get("/auth/login", (context) =>
    limited(context, "auth", 20)
      ? dashboardError(context, "RATE_LIMITED", 429, true)
      : login(context, dependencies, "sign-in", nowMs),
  );
  app.get("/auth/register", (context) =>
    limited(context, "auth", 20)
      ? dashboardError(context, "RATE_LIMITED", 429, true)
      : login(context, dependencies, "sign-up", nowMs),
  );
  app.get("/auth/callback", async (context) => {
    if (limited(context, "auth-callback", 30))
      return dashboardError(context, "RATE_LIMITED", 429, true);
    const client = dependencies.sessionClient;
    const secret = dependencies.config.csrfSecret;
    const state = openPkceState(
      secret ?? "",
      getCookie(context, stateCookie),
      nowMs(),
    );
    const code = context.req.query("code");
    if (
      !client ||
      !secret ||
      !state ||
      !code ||
      context.req.query("state") !== state.state
    )
      return dashboardError(context, "AUTH_CALLBACK_INVALID", 400);
    let completed;
    try {
      completed = await client.completeLogin({
        code,
        codeVerifier: state.verifier,
      });
    } catch (error) {
      if (isTerminalAuthError(error)) {
        clearPkceState(context);
        return dashboardError(context, "AUTH_CALLBACK_INVALID", 400);
      }
      context.header("Retry-After", "3");
      return dashboardError(
        context,
        "AUTHENTICATION_TEMPORARILY_UNAVAILABLE",
        503,
        true,
      );
    }
    deleteCookie(context, stateCookie, {
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "Lax",
    });
    try {
      setSessionCookie(
        context,
        completed.sealedSession,
        dependencies.config.sessionMaxAgeSeconds,
        nowMs(),
        true,
        dependencies.config.csrfSecret!,
      );
      const principal = resolveDashboardPrincipal(completed.session);
      if (!principal) {
        const organizations = await client.listOrganizations(
          completed.session.userId,
        );
        const csrfToken = createCsrfToken(secret, {
          sessionId: completed.session.sessionId,
          tenantId: "organization-selection",
        });
        return context.html(
          <OrganizationPicker
            organizations={organizations}
            csrfToken={csrfToken}
          />,
        );
      }
      dependencies.logger.write({
        event: "dashboard.auth.login",
        requestId: context.get("requestId"),
      });
      return context.redirect(state.next, 302);
    } catch {
      return dashboardError(context, "STORAGE_UNAVAILABLE", 503, true);
    }
  });
  // These form mutations are intentionally outside `/api/*`, so they need the
  // same bounded-body boundary before they read cookies, CSRF, or form data.
  app.use("/auth/logout", authMutationBodyLimit);
  app.post("/auth/logout", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    const body = await context.req.parseBody();
    const csrfToken =
      typeof body.csrfToken === "string" ? body.csrfToken : undefined;
    if (
      !loaded ||
      !requireCsrf(context, dependencies, loaded.principal, csrfToken)
    )
      return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
    const sealed = loaded.sealedSession;
    clearSessionCookies(context);
    dependencies.logger.write({
      event: "dashboard.auth.logout",
      requestId: context.get("requestId"),
    });
    const logoutUrl = sealed
      ? await dependencies.sessionClient
          ?.getLogoutUrl(sealed, `${dependencies.config.dashboardOrigin}/`)
          .catch(() => null)
      : null;
    const safeLogoutUrl = safeWorkosRedirect(logoutUrl);
    return safeLogoutUrl
      ? context.redirect(safeLogoutUrl, 302)
      : context.body(null, 204);
  });
  app.use("/auth/organization", authMutationBodyLimit);
  app.post("/auth/organization", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    const body = await context.req.parseBody();
    const csrfToken =
      typeof body.csrfToken === "string" ? body.csrfToken : undefined;
    const sealedSession =
      loaded?.sealedSession ?? getCookie(context, sessionCookie);
    const pending =
      !loaded && sealedSession && dependencies.sessionClient
        ? await dependencies.sessionClient
            .authenticate(sealedSession)
            .catch(() => null)
        : null;
    const csrfPrincipal = loaded?.principal;
    const csrfValid = csrfPrincipal
      ? requireCsrf(context, dependencies, csrfPrincipal, csrfToken)
      : Boolean(
          pending &&
          dependencies.config.csrfSecret &&
          isSameOriginMutation(
            context.req.raw,
            dependencies.config.dashboardOrigin,
          ) &&
          verifyCsrfToken(dependencies.config.csrfSecret, {
            sessionId: pending.sessionId,
            tenantId: "organization-selection",
            token: csrfToken,
          }),
        );
    if (!sealedSession || !csrfValid)
      return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
    const organizationId =
      typeof body.organizationId === "string" ? body.organizationId : "";
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(organizationId))
      return dashboardError(context, "VALIDATION_FAILED", 422);
    let refreshed;
    try {
      refreshed = await dependencies.sessionClient?.refresh(
        sealedSession,
        organizationId,
      );
    } catch (error) {
      if (isTerminalAuthError(error)) {
        clearSessionCookies(context);
        return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
      }
      context.header("Retry-After", "3");
      return dashboardError(
        context,
        "AUTHENTICATION_TEMPORARILY_UNAVAILABLE",
        503,
        true,
      );
    }
    const switchedPrincipal =
      refreshed?.kind === "ok"
        ? resolveDashboardPrincipal(refreshed.session)
        : null;
    if (
      !refreshed ||
      refreshed.kind !== "ok" ||
      !switchedPrincipal ||
      switchedPrincipal.organizationId !== organizationId
    ) {
      if (refreshed?.kind === "terminal") {
        clearSessionCookies(context);
        return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
      }
      return dashboardError(context, "ACCESS_DENIED", 403);
    }
    setSessionCookie(
      context,
      refreshed.sealedSession,
      dependencies.config.sessionMaxAgeSeconds,
      nowMs(),
      false,
      dependencies.config.csrfSecret,
    );
    return context.redirect("/dashboard", 303);
  });
  app.get("/", async (context) => dashboardPage(context, dependencies));
  app.get("/dashboard", async (context) =>
    dashboardPage(context, dependencies),
  );
  app.get("/dashboard/incidents/:incidentId", async (context) =>
    dashboardDetailPage(context, dependencies, context.req.param("incidentId")),
  );
  app.get("/api/incidents", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    if (!loaded) return authenticationFailure(context);
    const parsed = IncidentListQuerySchema.safeParse(context.req.query());
    if (!parsed.success)
      return dashboardError(context, "VALIDATION_FAILED", 422);
    try {
      return context.json(
        await listDashboardIncidents(dependencies.store, {
          tenantId: loaded.principal.tenantId,
          cursorSecret: dependencies.config.csrfSecret!,
          ...parsed.data,
        }),
      );
    } catch (error) {
      if (error instanceof Error && error.name === "DomainError")
        return dashboardError(context, "VALIDATION_FAILED", 422);
      return dashboardError(context, "STORAGE_UNAVAILABLE", 503, true);
    }
  });
  app.get("/api/incidents/:incidentId", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    if (!loaded) return authenticationFailure(context);
    try {
      return context.json(
        await readDashboardIncident(dependencies.store, {
          tenantId: loaded.principal.tenantId,
          incidentId: context.req.param("incidentId"),
        }),
      );
    } catch (error) {
      return dashboardError(
        context,
        error instanceof Error && error.name === "DomainError"
          ? "NOT_FOUND"
          : "STORAGE_UNAVAILABLE",
        error instanceof Error && error.name === "DomainError" ? 404 : 503,
        !(error instanceof Error && error.name === "DomainError"),
      );
    }
  });
  app.post("/api/incidents/:incidentId/approvals", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    if (!loaded || !requireCsrf(context, dependencies, loaded.principal))
      return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
    if (loaded.principal.role !== "soc_manager") {
      dependencies.logger.write({
        event: "dashboard.rbac.denied",
        requestId: context.get("requestId"),
        correlationId: context.get("correlationId"),
        incidentId: context.req.param("incidentId"),
        errorCode: "ROLE_REQUIRED",
        status: 403,
      });
      return dashboardError(context, "ACCESS_DENIED", 403);
    }
    if (limited(context, `decision:${loaded.principal.sessionRef}`, 12))
      return dashboardError(context, "RATE_LIMITED", 429, true);
    let refreshed;
    try {
      refreshed = await dependencies.sessionClient?.refresh(
        loaded.sealedSession,
        loaded.principal.organizationId,
      );
    } catch (error) {
      if (isTerminalAuthError(error)) {
        clearSessionCookies(context);
        return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
      }
      context.header("Retry-After", "3");
      return dashboardError(
        context,
        "AUTHENTICATION_TEMPORARILY_UNAVAILABLE",
        503,
        true,
      );
    }
    const principal =
      refreshed?.kind === "ok"
        ? resolveDashboardPrincipal(refreshed.session)
        : null;
    if (!refreshed || refreshed.kind !== "ok" || !principal) {
      if (refreshed?.kind === "terminal") clearSessionCookies(context);
      return dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
    }
    setSessionCookie(
      context,
      refreshed.sealedSession,
      dependencies.config.sessionMaxAgeSeconds,
      nowMs(),
      false,
      dependencies.config.csrfSecret,
    );
    const body = DashboardDecisionRequestSchema.safeParse(
      await context.req.json().catch(() => null),
    );
    if (!body.success) return dashboardError(context, "VALIDATION_FAILED", 422);
    try {
      return context.json(
        await decideDashboardApproval({
          store: dependencies.store,
          phase6Config: dependencies.phase6Config,
          principal,
          incidentId: context.req.param("incidentId"),
          body: body.data,
          correlationId: context.get("correlationId"),
          reconcileApprovalRun: dependencies.reconcileApprovalRun,
          clock: { now: () => new Date(nowMs()).toISOString() },
        }),
      );
    } catch (error) {
      return dashboardError(
        context,
        error instanceof DomainError
          ? "DECISION_REJECTED"
          : "STORAGE_UNAVAILABLE",
        error instanceof DomainError ? 409 : 503,
        !(error instanceof DomainError),
      );
    }
  });
  app.get("/api/incidents/:incidentId/events", async (context) => {
    const loaded = await loadPrincipal(context, dependencies);
    if (!loaded) return authenticationFailure(context);
    const incidentId = context.req.param("incidentId");
    let replay;
    try {
      replay = await validateSseReplay(
        dependencies.store,
        loaded.principal,
        incidentId,
        // EventSource is forbidden from setting custom headers.  SSR supplies
        // the first cursor in `after`; browser reconnects prefer its native
        // Last-Event-ID header, which is checked by the same strict parser.
        context.req.header("Last-Event-ID") ?? context.req.query("after"),
      );
    } catch (error) {
      return dashboardError(
        context,
        error instanceof DomainError ? "NOT_FOUND" : "STORAGE_UNAVAILABLE",
        error instanceof DomainError ? 404 : 503,
        !(error instanceof DomainError),
      );
    }
    if (!replay)
      return context.req.query("resync") === "stream"
        ? sseResyncResponse(context)
        : dashboardError(context, "RESYNC_REQUIRED", 409);
    // Connection limits aggregate over the session and tenant.  Including the
    // incident in the key made the previous limit trivially bypassable.
    const sessionKey = `session:${loaded.principal.sessionRef}`;
    const tenantKey = `tenant:${loaded.principal.tenantId}`;
    const ipKey = `ip:${clientKey(context)}`;
    const sessionCount = activeSse.get(sessionKey) ?? 0;
    const tenantCount = activeSse.get(tenantKey) ?? 0;
    const ipCount = activeSse.get(ipKey) ?? 0;
    if (
      sessionCount >= dependencies.config.sseMaxConnections ||
      tenantCount >= dependencies.config.sseMaxConnections * 8 ||
      ipCount >= dependencies.config.sseMaxConnections * 8
    )
      return dashboardError(context, "SSE_LIMIT_REACHED", 429);
    activeSse.set(sessionKey, sessionCount + 1);
    activeSse.set(tenantKey, tenantCount + 1);
    activeSse.set(ipKey, ipCount + 1);
    return sseResponse(context, {
      store: dependencies.store,
      principal: loaded.principal,
      incidentId,
      replay: replay.events,
      after: replay.after,
      release: () => {
        for (const key of [sessionKey, tenantKey, ipKey]) {
          const next = (activeSse.get(key) ?? 1) - 1;
          if (next <= 0) activeSse.delete(key);
          else activeSse.set(key, next);
        }
      },
    });
  });
}

async function login(
  context: Context<AppEnv>,
  dependencies: DashboardDependencies,
  intent: "sign-in" | "sign-up",
  nowMs: () => number,
) {
  const client = dependencies.sessionClient;
  const secret = dependencies.config.csrfSecret;
  if (!client || !secret)
    return dashboardError(context, "AUTH_CONFIGURATION_REQUIRED", 503, true);
  try {
    const started = await client.startLogin({ intent });
    const next = safeDashboardNext(context.req.query("next"));
    setCookie(
      context,
      stateCookie,
      sealPkceState(secret, {
        state: started.state,
        verifier: started.codeVerifier,
        next,
        issuedAtMs: nowMs(),
      }),
      { path: "/", httpOnly: true, secure: true, sameSite: "Lax", maxAge: 600 },
    );
    const authorizationUrl = safeWorkosRedirect(started.authorizationUrl);
    if (!authorizationUrl)
      return dashboardError(context, "AUTH_CONFIGURATION_REQUIRED", 503, true);
    return context.redirect(authorizationUrl, 302);
  } catch {
    return dashboardError(context, "AUTH_CONFIGURATION_REQUIRED", 503, true);
  }
}

async function dashboardPage(
  context: Context<AppEnv>,
  dependencies: DashboardDependencies,
) {
  const loaded = await loadPrincipal(context, dependencies);
  if (!loaded)
    return context.html(<LoginPage requestId={context.get("requestId")} />);
  const csrfToken = createCsrfToken(dependencies.config.csrfSecret!, {
    sessionId: loaded.principal.sessionRef,
    tenantId: loaded.principal.tenantId,
  });
  const query = IncidentListQuerySchema.safeParse(context.req.query());
  if (!query.success) return dashboardError(context, "VALIDATION_FAILED", 422);
  let data;
  try {
    data = await listDashboardIncidents(dependencies.store, {
      tenantId: loaded.principal.tenantId,
      cursorSecret: dependencies.config.csrfSecret!,
      ...query.data,
    });
  } catch {
    return context.html(
      <DashboardShell principal={loaded.principal} csrfToken={csrfToken}>
        <DashboardUnavailable message="Incident data could not be loaded. Retry this page." />
      </DashboardShell>,
      503,
    );
  }
  return context.html(
    <DashboardShell principal={loaded.principal} csrfToken={csrfToken}>
      <section aria-live="polite">
        <h2>Incidents</h2>
        <form
          method="get"
          action="/dashboard"
          class="card"
          aria-label="Filter incidents"
        >
          <label>
            Status
            <input name="status" value={query.data.status ?? ""} />
          </label>
          <label>
            Severity
            <input name="severity" value={query.data.severity ?? ""} />
          </label>
          <label>
            Kind
            <input name="kind" value={query.data.kind ?? ""} />
          </label>
          <button type="submit">Apply filters</button>
          <a href="/dashboard">Clear filters</a>
        </form>
        {data.items.length ? (
          data.items.map((item) => (
            <article class="card">
              <a href={`/dashboard/incidents/${item.incidentId}`}>
                {item.incidentId}
              </a>
              <p class="severity">
                {item.severity ?? "unclassified"} · {item.status}
              </p>
              <p class="muted">
                {item.kind} · {item.updatedAt}
              </p>
            </article>
          ))
        ) : (
          <p>No incidents are available for this tenant.</p>
        )}
        {data.page.nextCursor ? (
          <p>
            <a href={dashboardListHref(query.data, data.page.nextCursor)}>
              Next page
            </a>
          </p>
        ) : null}
      </section>
    </DashboardShell>,
  );
}

function dashboardListHref(
  query: Readonly<{
    kind?: string;
    status?: string;
    severity?: string;
    limit: number;
  }>,
  cursor: string,
): string {
  const params = new URLSearchParams({ cursor, limit: String(query.limit) });
  for (const [key, value] of Object.entries(query))
    if (key !== "limit" && value) params.set(key, String(value));
  return `/dashboard?${params.toString()}`;
}

async function dashboardDetailPage(
  context: Context<AppEnv>,
  dependencies: DashboardDependencies,
  incidentId: string,
) {
  const loaded = await loadPrincipal(context, dependencies);
  if (!loaded)
    return context.html(<LoginPage requestId={context.get("requestId")} />);
  let detail;
  try {
    detail = await readDashboardIncident(dependencies.store, {
      tenantId: loaded.principal.tenantId,
      incidentId,
    });
  } catch (error) {
    if (!(error instanceof Error && error.name === "DomainError")) {
      const csrfToken = createCsrfToken(dependencies.config.csrfSecret!, {
        sessionId: loaded.principal.sessionRef,
        tenantId: loaded.principal.tenantId,
      });
      return context.html(
        <DashboardShell principal={loaded.principal} csrfToken={csrfToken}>
          <DashboardUnavailable message="Incident data could not be loaded. Retry this page." />
        </DashboardShell>,
        503,
      );
    }
    return dashboardError(context, "NOT_FOUND", 404, false);
  }
  const csrfToken = createCsrfToken(dependencies.config.csrfSecret!, {
    sessionId: loaded.principal.sessionRef,
    tenantId: loaded.principal.tenantId,
  });
  return context.html(
    <DashboardShell principal={loaded.principal} csrfToken={csrfToken}>
      <IncidentDetail
        detail={detail}
        csrfToken={csrfToken}
        canDecide={loaded.principal.role === "soc_manager"}
      />
    </DashboardShell>,
  );
}

async function loadPrincipal(
  context: Context<AppEnv>,
  dependencies: DashboardDependencies,
): Promise<Readonly<{
  principal: DashboardPrincipal;
  sealedSession: string;
}> | null> {
  const sealedSession = getCookie(context, sessionCookie);
  if (!sealedSession || !dependencies.sessionClient) return null;
  if (
    !dependencies.config.csrfSecret ||
    !openSessionIssuedAt(
      dependencies.config.csrfSecret,
      getCookie(context, issuedCookie),
      (dependencies.nowMs ?? Date.now)(),
      dependencies.config.sessionMaxAgeSeconds,
    )
  ) {
    clearSessionCookies(context);
    return null;
  }
  try {
    let currentSealedSession = sealedSession;
    let session =
      await dependencies.sessionClient.authenticate(currentSealedSession);
    if (!session) {
      const refreshed =
        await dependencies.sessionClient.refresh(currentSealedSession);
      if (refreshed.kind === "terminal") {
        clearSessionCookies(context);
        return null;
      }
      session = refreshed.session;
      currentSealedSession = refreshed.sealedSession;
      setSessionCookie(
        context,
        refreshed.sealedSession,
        dependencies.config.sessionMaxAgeSeconds,
        (dependencies.nowMs ?? Date.now)(),
        false,
        dependencies.config.csrfSecret,
      );
    }
    const principal = session ? resolveDashboardPrincipal(session) : null;
    if (!principal) {
      clearSessionCookies(context);
      return null;
    }
    return { principal, sealedSession: currentSealedSession };
  } catch {
    // SDK/network exceptions are transient until an explicit terminal result.
    context.set("dashboardAuthTransient", true);
    context.header("Retry-After", "3");
    return null;
  }
}
function authenticationFailure(context: Context<AppEnv>) {
  return context.get("dashboardAuthTransient")
    ? dashboardError(
        context,
        "AUTHENTICATION_TEMPORARILY_UNAVAILABLE",
        503,
        true,
      )
    : dashboardError(context, "AUTHENTICATION_REQUIRED", 401);
}
function clearSessionCookies(context: Context<AppEnv>) {
  for (const name of [sessionCookie, issuedCookie])
    deleteCookie(context, name, {
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "Lax",
    });
}
function clearPkceState(context: Context<AppEnv>) {
  deleteCookie(context, stateCookie, {
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  });
}
/** WorkOS exposes terminal OAuth input failures as `invalid_grant`/4xx. */
function isTerminalAuthError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as Readonly<{
    code?: unknown;
    error?: unknown;
    status?: unknown;
    statusCode?: unknown;
  }>;
  return (
    candidate.code === "invalid_grant" ||
    candidate.error === "invalid_grant" ||
    candidate.status === 400 ||
    candidate.status === 401 ||
    candidate.statusCode === 400 ||
    candidate.statusCode === 401
  );
}
function requireCsrf(
  context: Context<AppEnv>,
  dependencies: DashboardDependencies,
  principal: DashboardPrincipal,
  formToken?: string,
) {
  return (
    Boolean(dependencies.config.csrfSecret) &&
    isSameOriginMutation(
      context.req.raw,
      dependencies.config.dashboardOrigin,
    ) &&
    verifyCsrfToken(dependencies.config.csrfSecret!, {
      sessionId: principal.sessionRef,
      tenantId: principal.tenantId,
      token: context.req.header("X-CSRF-Token") ?? formToken,
    })
  );
}
function setSessionCookie(
  context: Context<AppEnv>,
  value: string,
  maxAge: number,
  nowMs = Date.now(),
  createLifetime = false,
  secret?: string,
) {
  const issuedAt = secret
    ? openSessionIssuedAt(
        secret,
        getCookie(context, issuedCookie),
        nowMs,
        maxAge,
      )
    : null;
  const effectiveIssuedAt = issuedAt ?? (createLifetime ? nowMs : nowMs);
  const remaining = Math.max(
    0,
    maxAge - Math.ceil((nowMs - effectiveIssuedAt) / 1000),
  );
  if (secret && (createLifetime || !issuedAt))
    setCookie(
      context,
      issuedCookie,
      sealSessionIssuedAt(secret, effectiveIssuedAt),
      {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge,
      },
    );
  setCookie(context, sessionCookie, value, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: remaining,
  });
}
function dashboardError(
  context: Context<AppEnv>,
  code: string,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 503,
  retryable = false,
) {
  return context.json(
    {
      code,
      message: "The dashboard request could not be completed.",
      requestId: context.get("requestId"),
      retryable,
    },
    status,
  );
}
