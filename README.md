# Security Incident Triage and Response

Phase 2 provides signed Hono ingestion and an outbox-backed, asynchronous Mastra workflow start. It is intentionally mock-only: it does not install WorkOS AuthKit, connect to WorkOS or Upstash, or process real identities.

## Requirements

- Node.js 22.13.0 or newer
- npm

## Installation and local configuration

```sh
npm ci
cp .env.example .env
openssl rand -hex 32
```

Put separately generated values in `ALERT_WEBHOOK_SECRET` and `WORKOS_WEBHOOK_SECRET`. The local LibSQL database needs no token. An OpenAI API key is needed only when invoking the smoke agent; ingestion and the Phase 2 workflow do not call a model.

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

A new or equivalent retry returns `202` only after incident, alert, initial timeline and outbox commit. The dispatcher then publishes `security.alert.received` through Mastra's configured PubSub, and the worker uses a deterministic run ID with `startAsync`. The Phase 2 workflow only transitions `received` to `investigating`; investigation, agents and providers belong to later phases.

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
npm test
npm run build
npm run audit
```
