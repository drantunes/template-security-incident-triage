# Security Incident Triage and Response

Phase 4 adds deterministic identity, endpoint, and cloud evidence collection, bounded supervisor agents, integrity-checked persistence, and correlation before the existing fail-closed RAG step. It remains mock-only: it does not connect to WorkOS, IPinfo, an EDR, or Upstash, classify severity, propose containment, or execute actions.

## Requirements

- Node.js 22.13.0 or newer
- npm

## Installation and local configuration

```sh
npm ci
cp .env.example .env
openssl rand -hex 32
```

Put separately generated values in `ALERT_WEBHOOK_SECRET` and `WORKOS_WEBHOOK_SECRET`. The local LibSQL database needs no token. An OpenAI API key is needed when the Phase 4 workflow invokes its registered agents; automated tests inject deterministic model doubles and make no model or network calls. Runbook retrieval uses local BGE Small EN v1.5 embeddings with 384 dimensions and does not require an API key.

## Runbook validation and indexing

Validate the strict frontmatter, canonical sections, action allowlist, links, deterministic chunk IDs and hashes without network access:

```sh
npm run runbooks:validate
```

Index all three validated runbooks into immutable physical LibSQL vector indexes and atomically activate one generation per incident kind:

```sh
npm run runbooks:index
```

The first explicit indexing run may download BGE Small EN v1.5 into `RUNBOOK_FASTEMBED_CACHE_DIR`; default tests and CI use deterministic test embeddings and never download a model. Repeating the command is idempotent for unchanged bytes. A changed published SemVer is rejected and must be introduced as a new version.

Inspect the active pointers, CAS revisions and append-only activation ledger before maintenance:

```sh
npm run runbooks:inspect
```

Rollback accepts only a previously activated, retired and intact generation. It reads back the exact physical vector index, then atomically switches the pointer with the inspected revision and records a `rollback` event:

```sh
npm run runbooks:rollback -- <generation-id> <expected-revision>
```

Cleanup requires the exact retired/failed generation, index and chunk count. It defaults to dry-run, refuses active or in-flight retrievals, establishes a durable cleanup claim, revalidates immediately before deletion and never uses a wildcard:

```sh
npm run runbooks:cleanup -- <generation-id> <index-name> <chunk-count> --dry-run
npm run runbooks:cleanup -- <generation-id> <index-name> <chunk-count> --execute
```

Retrieval ownership uses a 60-second fenced lease. A retry during a live lease is refused; after expiry, one CAS winner renews the lease while preserving the exact generation and policy selection. An expired owner cannot persist success or failure, and cleanup blocks valid leases while safely claiming a generation whose retrieval lease is stale.

## Running

Start Mastra Studio and the single Hono server together:

```sh
npm run dev
```

Studio is available at `http://localhost:4111`; Hono health is at `http://localhost:3000/health`. Only the Hono server owns the domain worker and outbox polling loop. Studio loads the registered workflows and shared LibSQL storage without starting a second dispatcher.

The server startup order is migrations, Mastra workers, domain subscription, outbox reconciliation/polling, then HTTP bind. Shutdown stops polling, unsubscribes, flushes, closes HTTP/storage and shuts Mastra down.

## Signed synthetic alert

The demo endpoint requires `Content-Type: application/json` and:

```text
X-Alert-Signature: t=<unix_ms>,v1=<hmac_sha256_hex>
```

The digest covers the exact bytes of `<unix_ms>.<raw-body>`, with a fixed absolute tolerance of 300 seconds. JSON whitespace or byte changes invalidate the signature. Multiple `v1` values are accepted for rotation.

Generate a header for the versioned synthetic fixture and send those exact file bytes:

```sh
SIGNATURE="$(npm run --silent fixture:sign)"
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H "X-Alert-Signature: ${SIGNATURE}" \
  --data-binary @scripts/fixtures/phase2-alert.json \
  http://localhost:3000/webhooks/alerts
```

A new or equivalent retry returns `202` only after incident, alert, initial timeline and outbox commit. The dispatcher then publishes `security.alert.received` through Mastra's configured PubSub, and the worker uses a deterministic run ID with `startAsync`. The workflow transitions `received` to `investigating`, validates one trusted tenant/incident/subject/run context, starts identity, endpoint and cloud gather steps with Mastra `.parallel()`, and persists every valid mock fact before correlation. Source failures remain explicit gaps; integrity or storage failures fail closed. Correlation uses only verified evidence IDs and records ordering, relations, contradictions and missing sources without severity or actions. The unchanged RAG step then resolves the unique active runbook generation and persists its exact citations. Missing, inactive, ambiguous, corrupted, low-score or unavailable runbooks still fail closed without a global fallback.

`/webhooks/workos` is a synthetic adapter using `WorkOS-Signature` with the same cryptographic semantics. It supports only `mock.user.role_changed`, `mock.session.country_login` and `mock.session.unknown_device`. Unknown/incompatible authenticated mock events are acknowledged only after a redacted dead-letter record; this is not complete WorkOS event support.

## Reliability and privacy

- Invalid signatures, schemas and storage fail closed.
- Raw payloads, signature headers, secrets, cookies and PII are not logged or persisted; only `sha256:` references are stored.
- Outbox publication uses an expiring lease/fence, bounded retry/backoff and dead-letter.
- Publish-before-mark and local transport loss are reconciled against the durable workflow marker.
- HTTP acceptance never waits for workflow completion.

## Quality gates

```sh
npm run format:check
npm run lint
npm run typecheck
npm run runbooks:validate
npm test
npm run build
npm run audit
```
