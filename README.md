# Security Incident Triage and Response

## Requirements

- Node.js 22.13.0 or newer
- npm

## Installation

```sh
npm ci
```

## Local configuration

Copy `.env.example` to `.env`. The local LibSQL database works with the default file URL and does not require a token. An OpenAI API key is only needed when invoking the smoke agent; discovery, the placeholder workflow, and the health check do not call a model.

## Running

Start Mastra Studio and the Hono application together:

```sh
npm run dev
```

Mastra Studio is available at `http://localhost:4111`. The Hono health check is available at `http://localhost:3000/health`.

Build and start the Hono application:

```sh
npm run build
npm start
```

## Tests

```sh
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
npm run audit
```
