import { startDevelopment } from "../src/dev-supervisor.js";

await startDevelopment({ installSignalHandlers: true });
