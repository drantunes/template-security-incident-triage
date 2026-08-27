import { serve, type ServerType } from "@hono/node-server";
import { MastraServer } from "@mastra/hono";
import { Hono } from "hono";

import { mastra } from "./mastra/index.js";

const DEFAULT_PORT = 3000;

export async function createApp(): Promise<Hono> {
  const app = new Hono();

  app.use("*", async (context, next) => {
    await next();
    context.header("Cache-Control", "no-store");
    context.header("Content-Security-Policy", "default-src 'none'");
    context.header("X-Content-Type-Options", "nosniff");
    context.header("X-Frame-Options", "DENY");
  });

  app.get("/health", (context) => context.json({ status: "ok" }));

  const server = new MastraServer({ app, mastra });
  await server.init();

  return app;
}

export async function startServer(port = readPort()): Promise<ServerType> {
  const app = await createApp();
  const server = serve({ fetch: app.fetch, port });

  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });

  return server;
}

function readPort(): number {
  const value = process.env.PORT;
  if (!value) return DEFAULT_PORT;

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be an integer between 1 and 65535.");
  }

  return port;
}

if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
) {
  const port = readPort();
  await startServer(port);
  console.log(`Hono server listening on http://localhost:${port}`);
}
