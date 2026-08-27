import { readdir } from "node:fs/promises";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { submitPlanTool } from "@mastra/core/tools";
import type { Mastra } from "@mastra/core/mastra";
import type { LibSQLStore } from "@mastra/libsql";
import type { Hono } from "hono";

import { smokeAgent } from "../src/mastra/agents/smoke-agent.js";
import { baselineWorkflow } from "../src/mastra/workflows/baseline-workflow.js";
import {
  createTempDatabase,
  type TempDatabase,
} from "./helpers/temp-libsql.js";

let mastra: Mastra;
let storage: LibSQLStore;
let createApp: () => Promise<Hono>;
let database: TempDatabase | undefined;
let previousStorageUrl: string | undefined;
let initialWorkspaceDatabases: string[] = [];

beforeAll(async () => {
  initialWorkspaceDatabases = await listWorkspaceDatabases();
  database = await createTempDatabase();
  previousStorageUrl = process.env.MASTRA_STORAGE_URL;
  process.env.MASTRA_STORAGE_URL = database.url;

  ({ mastra, storage } = await import("../src/mastra/index.js"));
  ({ createApp } = await import("../src/server.js"));
});

afterAll(async () => {
  try {
    await storage?.close();
  } finally {
    try {
      await database?.cleanup();
    } finally {
      if (previousStorageUrl === undefined) {
        delete process.env.MASTRA_STORAGE_URL;
      } else {
        process.env.MASTRA_STORAGE_URL = previousStorageUrl;
      }
    }
  }
  expect(await listWorkspaceDatabases()).toEqual(initialWorkspaceDatabases);
});

async function listWorkspaceDatabases(): Promise<string[]> {
  return (await readdir(process.cwd()))
    .filter((name) => name === "mastra.db" || name.startsWith("mastra.db-"))
    .sort();
}

describe("Phase 0 baseline", () => {
  it("registers the smoke agent and placeholder workflow", () => {
    expect(mastra.getAgent("smokeAgent")).toBe(smokeAgent);
    expect(mastra.getWorkflow("baselineWorkflow")).toBe(baselineWorkflow);
  });

  it("registers the presentation-only submit-plan spike", () => {
    expect(submitPlanTool.id).toBe("submit_plan");
    expect(submitPlanTool.inputSchema).toBeDefined();
    expect(submitPlanTool.suspendSchema).toBeDefined();
    expect(submitPlanTool.resumeSchema).toBeDefined();
  });

  it("runs the deterministic placeholder workflow", async () => {
    const run = await baselineWorkflow.createRun();
    const result = await run.start({ inputData: { message: "smoke" } });

    expect(result.status).toBe("success");
    if (result.status === "success") {
      expect(result.result).toEqual({ message: "smoke", status: "ready" });
    }
  });

  it("serves a minimal health response with defensive headers", async () => {
    const app = await createApp();
    const response = await app.request("/health");

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toBe(
      "default-src 'none'",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
  });
});
