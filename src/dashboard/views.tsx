/** @jsxImportSource hono/jsx */
import type { FC } from "hono/jsx";

import type { DashboardPrincipal } from "../auth/dashboard-principal.js";
import type { DashboardOrganization } from "../auth/workos-session.js";
import type { readDashboardIncident } from "./queries.js";

type DashboardIncidentDetail = Awaited<
  ReturnType<typeof readDashboardIncident>
>;

export const DashboardShell: FC<
  Readonly<{
    principal: DashboardPrincipal;
    csrfToken: string;
    children: unknown;
  }>
> = ({ principal, csrfToken, children }) => (
  <html>
    <head>
      <meta charSet="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>SOC dashboard</title>
      <link rel="stylesheet" href="/assets/dashboard.css" />
    </head>
    <body>
      <main>
        <header>
          <h1>Security incident triage</h1>
          <p class="muted">
            Tenant: {principal.tenantId} · Role: {principal.role}
          </p>
          <form method="post" action="/auth/logout">
            <input type="hidden" name="csrfToken" value={csrfToken} />
            <button type="submit">Log out</button>
          </form>
        </header>
        {children}
        <script src="/assets/dashboard.js" />
      </main>
    </body>
  </html>
);

export const LoginPage: FC<Readonly<{ requestId: string }>> = ({
  requestId,
}) => (
  <html>
    <head>
      <meta charSet="utf-8" />
      <title>Sign in</title>
      <link rel="stylesheet" href="/assets/dashboard.css" />
    </head>
    <body>
      <main>
        <h1>Security incident triage</h1>
        <p>Sign in to access your organization’s incidents.</p>
        <p>
          <a href="/auth/login">Sign in</a> ·{" "}
          <a href="/auth/register">Register</a>
        </p>
        <small class="muted">Request: {requestId}</small>
      </main>
    </body>
  </html>
);

export const DashboardUnavailable: FC<Readonly<{ message: string }>> = ({
  message,
}) => (
  <section class="card" role="alert" aria-live="assertive">
    <h2>Dashboard temporarily unavailable</h2>
    <p>{message}</p>
    <p>
      <a href="/dashboard">Retry dashboard</a>
    </p>
  </section>
);

export const OrganizationPicker: FC<
  Readonly<{
    organizations: readonly DashboardOrganization[];
    csrfToken: string;
  }>
> = ({ organizations, csrfToken }) => (
  <html>
    <head>
      <meta charSet="utf-8" />
      <title>Select organization</title>
      <link rel="stylesheet" href="/assets/dashboard.css" />
    </head>
    <body>
      <main>
        <h1>Select an organization</h1>
        {organizations.length ? (
          <form method="post" action="/auth/organization">
            <input type="hidden" name="csrfToken" value={csrfToken} />
            <label>
              Organization
              <select name="organizationId" required>
                {organizations.map((organization) => (
                  <option value={organization.organizationId}>
                    {organization.organizationName} ({organization.role})
                  </option>
                ))}
              </select>
            </label>
            <button type="submit">Continue</button>
          </form>
        ) : (
          <p role="status">
            No active organization with an approved role is available.
          </p>
        )}
      </main>
    </body>
  </html>
);

export const IncidentDetail: FC<
  Readonly<{
    detail: DashboardIncidentDetail;
    csrfToken: string;
    canDecide: boolean;
  }>
> = ({ detail, csrfToken, canDecide }) => (
  <section
    aria-live="polite"
    data-incident-id={detail.incident.incidentId}
    data-timeline-cursor={detail.timelineCursor}
    data-can-decide={String(canDecide)}
    data-csrf-token={csrfToken}
  >
    <p data-live-status role="status" class="muted">
      Live timeline connecting.
    </p>
    <p>
      <a href="/dashboard">← All incidents</a>
    </p>
    <h2>{detail.incident.incidentId}</h2>
    <p class="severity" data-incident-summary>
      {detail.incident.severity ?? "unclassified"} · {detail.incident.status}
    </p>
    <section
      class="card"
      aria-labelledby="evidence-heading"
      data-evidence-projection
    >
      <h3 id="evidence-heading">Evidence</h3>
      {detail.evidence.map((evidence) => (
        <p
          class={
            evidence.state === "fact"
              ? "fact"
              : evidence.state === "missing"
                ? "missing"
                : "hypothesis"
          }
        >
          {evidence.state === "missing" ? "Missing evidence" : evidence.state}:{" "}
          {evidence.source} / {evidence.provider}; confidence{" "}
          {evidence.confidence}; observed {evidence.observedAt}
        </p>
      ))}
    </section>
    <div data-triage-projection>
      {detail.triage ? (
        <>
          <section class="card" aria-labelledby="summary-heading">
            <h3 id="summary-heading">Summary and runbook</h3>
            <p data-triage-summary>{detail.triage.summary}</p>
            <p data-runbook>Runbook: {detail.triage.runbook}</p>
            <h4>Facts</h4>
            {detail.triage.facts.map((fact: string) => (
              <p class="fact">Fact: {fact}</p>
            ))}
            <h4>Hypotheses</h4>
            {detail.triage.hypotheses.map((hypothesis: string) => (
              <p class="hypothesis">Hypothesis: {hypothesis}</p>
            ))}
          </section>
          <section class="card" aria-labelledby="plan-heading">
            <h3 id="plan-heading">Authoritative containment plan</h3>
            {detail.triage.actions.map((action) => (
              <article>
                <h4>{action.actionId}</h4>
                <p>
                  {action.type} · target {action.targetRef}
                </p>
                <p>Impact: {action.impact}</p>
                <p>Preconditions: {action.preconditions.join("; ")}</p>
                <p>Rollback: {action.rollback}</p>
                <p>Verification: {action.verification}</p>
              </article>
            ))}
            {canDecide &&
            detail.plan &&
            detail.approval?.decision === null &&
            detail.incident.status === "awaiting_approval" &&
            Date.parse(detail.plan.expiresAt) > Date.now() ? (
              <button type="button" data-open-decision>
                Review decision
              </button>
            ) : (
              <p class="muted">
                {detail.plan
                  ? "Decision unavailable: the plan is stale, expired, already decided, or your role is not SOC manager. Refresh to obtain the authoritative state."
                  : "Decision unavailable: no current authoritative plan exists."}
              </p>
            )}
          </section>
        </>
      ) : null}
    </div>
    <section
      class="card"
      aria-labelledby="approval-heading"
      data-operational-projection
    >
      <h3 id="approval-heading">Approval and execution outcome</h3>
      <p data-plan-binding>
        {detail.plan
          ? `Hash v${detail.plan.planHashVersion}: ${detail.plan.planHash}; expires ${detail.plan.expiresAt}`
          : "No current authoritative plan."}
      </p>
      {detail.approval ? (
        <p data-approval-status>
          Approval: {detail.approval.decision ?? "pending"}
          {detail.approval.decidedAt
            ? ` · decided ${detail.approval.decidedAt}`
            : ""}
          {detail.approval.reason ? ` · reason: ${detail.approval.reason}` : ""}
        </p>
      ) : (
        <p class="muted">No approval has been requested.</p>
      )}
      <p data-outcome-status>
        Outcome: {detail.outcome.status} · completed{" "}
        {detail.outcome.completedCount} · failed {detail.outcome.failedCount}
      </p>
      <ul data-actions>
        {detail.actions.map((action) => (
          <li>
            {action.actionId} · {action.type} · {action.status}
          </li>
        ))}
      </ul>
    </section>
    <section class="card" aria-labelledby="timeline-heading">
      <h3 id="timeline-heading">Timeline</h3>
      <div data-timeline>
        {detail.timeline.map((event) => (
          <p data-timeline-event={String(event.sequence)}>
            {event.sequence}. {event.type} · {event.occurredAt}
            {Object.entries(event.payloadRedacted).map(
              ([key, value]) => ` · ${key}: ${String(value)}`,
            )}
          </p>
        ))}
      </div>
    </section>
    <div data-decision-host>
      {canDecide &&
      detail.plan &&
      detail.approval?.decision === null &&
      detail.incident.status === "awaiting_approval" &&
      Date.parse(detail.plan.expiresAt) > Date.now() ? (
        <dialog id="decision-dialog" aria-labelledby="decision-heading">
          <h3 id="decision-heading">Confirm containment decision</h3>
          <form
            method="dialog"
            data-decision-form
            data-incident-id={detail.incident.incidentId}
            data-plan-binding={`${detail.plan.planId}:${detail.plan.planHashVersion}:${detail.plan.planHash}:${detail.plan.expiresAt}`}
          >
            <input type="hidden" name="csrfToken" value={csrfToken} />
            <input type="hidden" name="planId" value={detail.plan.planId} />
            <input
              type="hidden"
              name="planHashVersion"
              value={String(detail.plan.planHashVersion)}
            />
            <input type="hidden" name="planHash" value={detail.plan.planHash} />
            <input
              type="hidden"
              name="planExpiresAt"
              value={detail.plan.expiresAt}
            />
            <label>
              Decision
              <select name="decision">
                <option value="approved">Approve</option>
                <option value="rejected">Reject</option>
              </select>
            </label>
            <label>
              Rejection reason (required for rejection, max 2000 characters)
              <textarea
                name="reason"
                maxLength={2000}
                aria-describedby="reason-help"
              />
            </label>
            <p id="reason-help">
              Approval always requires this explicit confirmation.
            </p>
            <p data-decision-error role="alert" />
            <button type="submit">Confirm decision</button>
            <button type="button" data-close-dialog>
              Cancel
            </button>
          </form>
        </dialog>
      ) : null}
    </div>
  </section>
);
