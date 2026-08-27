import { startServerRuntime } from "./background/runtime.js";

const runtime = await startServerRuntime();
console.log(`Hono server listening on http://localhost:${runtime.port}`);

let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  await runtime.stop();
};

process.once("SIGINT", stop);
process.once("SIGTERM", stop);
