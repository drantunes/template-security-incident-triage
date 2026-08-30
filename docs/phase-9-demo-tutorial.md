# Phase 9 demo tutorial

These commands are intentionally offline in `mock` mode. They create an
isolated LibSQL database and a permission-restricted ownership journal under
`.mastra/demo-runs`; no WorkOS, IPinfo, Linear, Upstash, or production target
is contacted.

## Preconditions

Use Node `>=22.13.0`, install the locked dependencies with `npm ci`, and use a
fresh, explicitly named root when reproducing a scenario. Do not delete
`.mastra/demo-runs`: it can contain another run's audit/recovery journal.

```sh
demo_root="$(mktemp -d)"
npm --silent run demo -- preflight --scenario privilege --mode mock
```

The preflight record reports `network: blocked`. The versioned entrypoint emits
JSONL on stdout; use `npm --silent run` as shown so npm adds no banner. Use IDs
from `approval_required` rather than parsing prose.

## Privilege change

```sh
npm --silent run demo -- run --scenario privilege --run-key phase9-privilege-001 --root "$demo_root"
```

The synthetic subject changes from `member` to `admin`. The output reaches
`awaiting_approval`; after a decision, terminal verification reports
`RB-IDENTITY-001`, the policy-derived severity, and verified action types. The
alert was accepted by `POST /webhooks/alerts` with its HMAC; the runner never
calls a containment adapter directly.

## Login from a disallowed country

```sh
npm --silent run demo -- run --scenario country --run-key phase9-country-001 --root "$demo_root"
```

This fixture uses documentation address `198.51.100.8`, which the mock maps to
`CA` under a tenant `US-only` policy. It reaches `awaiting_approval`; terminal
verification after a decision reports `RB-IDENTITY-002` and the actions selected
from persisted policy evidence.

## Unknown device

```sh
npm --silent run demo -- run --scenario device --run-key phase9-device-001 --root "$demo_root"
npm --silent run demo -- run --scenario device --run-key phase9-device-001 --decision approve --root "$demo_root"
```

The fixture contains an opaque signed device credential bound to tenant, subject,
device, expiry, and a one-shot LibSQL nonce. Its device ID is absent from the
tenant and subject-scoped allowed list. The first command reaches
`awaiting_approval`; the second reopens the same persisted run through the mock
approval authority and emits `terminal` then `verification` for
`RB-IDENTITY-003`. The demo never collects a browser fingerprint.

## Inspect, decide, repeat, and clean up

Copy `demoRunId` from a JSON record:

```sh
npm --silent run demo -- inspect --demo-run-id <demoRunId> --root "$demo_root"
npm --silent run demo -- run --scenario privilege --run-key phase9-privilege-001 --decision approve --root "$demo_root"
npm --silent run demo -- run --scenario country --run-key phase9-country-001 --decision reject --root "$demo_root"
npm --silent run demo -- run --scenario device --run-key phase9-device-001 --decision approve --root "$demo_root"
npm --silent run demo -- cleanup --demo-run-id <demoRunId> --confirm-cleanup --root "$demo_root"
npm --silent run demo -- cleanup --demo-run-id <demoRunId> --confirm-cleanup --root "$demo_root"
```

The second `run` command reopens the same persisted database and submits a
one-shot decision through the existing mock approval authority; it does not
manufacture a resume payload. It emits terminal and verification records only
after the incident, workflow marker, approval, timeline, actions, attempts and
deliveries converge. Cleanup is idempotent and removes only the exact database
registered by that run's ownership journal, after a content precondition check.
Reusing a terminal scenario and run key revalidates its authoritative projection
and fails closed if any persisted action type, target, input, idempotency key,
attempt, effect or delivery no longer matches the approved plan; choose a new
run key for a new fixture. A pre-existing `<demoRunId>.db` or SQLite sidecar is
rejected before the runner opens it, and cleanup cannot adopt it.
Reject executes no containment. `inspect` reports durable journal state; use
terminal/verification records for runbook, severity, outcome, and verified
actions.

## Locate the same run in dashboard, SSE, and the Studio equivalent

After any `awaiting_approval` or terminal record, copy its `demoRunId` and run
the versioned local observer against the **same** root:

```sh
npm --silent run demo:surfaces -- --demo-run-id <demoRunId> --root "$demo_root"
```

Its one JSON record contains the unchanged `incidentId`, `workflowRunId`,
`approvalId`, and `planId` in `ids`, plus three observations made over that
owned database:

- `dashboard` is the existing F7 tenant-scoped dashboard detail read model.
  Compare `dashboard.incident.incidentId`, `workflowRunId`, status, approval,
  actions, and timeline to the CLI records.
- `sse.events` is the existing F7 authenticated SSE replay boundary before
  HTTP framing. It must contain the same `incidentId` and the same ordered,
  redacted timeline as `dashboard.timeline`.
- `mastraRun` is the local, durable equivalent for the Mastra Studio run view.
  Compare its `workflowId`, `workflowRunId`, incident ID, and status with the
  CLI and dashboard fields.

Studio's interactive UI cannot be automated safely by this offline harness, so
this command does not start Studio or a server. It uses a fixture-scoped mock
`soc_manager` principal only as the tenant authorization input required by the
existing F7 dashboard/SSE functions; it neither creates a cookie nor bypasses
the Phase 6 approval authority. The command reads no `.env` and registers no
new HTTP endpoint.

For an `awaiting_approval` observation, the dashboard status is
`awaiting_approval`, the durable Mastra-equivalent run status is `running`, the
approval decision is `null`, all planned actions remain `pending`, and there
are zero containment attempts/effects. After approve/reject/expire, the same
command instead validates the applicable terminal projection before publishing
the three surfaces.

## Controlled expiry: zero containment, then observe and clean

Use a new key so this is a separate owned run. `expire` advances only the
Phase 6 dispatcher clock to one millisecond after the persisted approval
expiry. It does not edit `expires_at`, synthesize an approval, or invoke a
containment adapter.

```sh
npm --silent run demo -- run --scenario privilege --run-key phase9-expiry-001 --root "$demo_root"
npm --silent run demo -- run --scenario privilege --run-key phase9-expiry-001 --decision expire --root "$demo_root"
npm --silent run demo:surfaces -- --demo-run-id <expiryDemoRunId> --root "$demo_root"
npm --silent run demo -- cleanup --demo-run-id <expiryDemoRunId> --confirm-cleanup --root "$demo_root"
```

The terminal and verification records report `outcome:"expired"`. The surface
record must show dashboard incident status `failed`, Mastra run status
`completed`, exactly one `approval.expired` SSE event, pending actions, and no
containment attempts or effects. The explicit cleanup remains idempotent and
removes only the database owned by `<expiryDemoRunId>`.

## Hermetic UI boundary

Do not use the general server or Studio entrypoints, or a hand-written curl,
as part of this mock tutorial. They are not the hermetic Phase 9 boundary; in
particular, the server entrypoint may load a local `.env`. This tutorial
intentionally contains no command that reads
`.env`, assumes a dashboard session, creates a cookie, or contacts a provider.

## Staging boundary

```sh
DEMO_MODE=staging DEMO_STAGING_TARGET_ORGANIZATION_ID=<allowlisted-org> \
  DEMO_STAGING_TARGET_USER_ID=<allowlisted-user> \
  DEMO_STAGING_TARGET_ROLE=<allowlisted-role> \
  DEMO_STAGING_TARGET_SESSION_ID=<allowlisted-session> \
  DEMO_STAGING_TARGET_DEVICE_ID=<synthetic-device> \
  DEMO_STAGING_ALLOWED_SESSION_IDS=<allowlisted-session> \
  DEMO_STAGING_ALLOWED_DEVICE_IDS=<synthetic-device> \
  DEMO_STAGING_OPERATION=revoke_session \
  npm --silent run demo -- preflight --scenario device --mode staging --real --confirm
```

This is a hermetic capability report only: it performs no network request or
external mutation. It reports `require_reauthentication` and
`mark_device_for_review` as `unsupported` in staging. Any future external
read, provider call, approval, containment, or cleanup needs separate nominal
HITL authorization from Diego for the exact provider and synthetic target.

## Troubleshooting

- `DEMO_STAGING_PRECONDITION_FAILED`: staging flags or `DEMO_MODE` are absent;
  no request was attempted.
- `DEMO_PRODUCTION_BLOCKED`: production is never a demo target.
- `DEMO_JOURNAL_TAMPERED` or `DEMO_CLEANUP_OWNERSHIP_DENIED`: stop and inspect
  the journal; do not delete or overwrite a divergent resource.
- A timeout or interruption leaves the journal in place for `inspect` and the
  explicit, bounded cleanup command; it does not attempt automatic rollback.
