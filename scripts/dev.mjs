import { spawn } from "node:child_process";
import { join } from "node:path";

const root = process.cwd();
const mastraExecutable = join(
  root,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "mastra.cmd" : "mastra",
);

const children = [
  spawn(mastraExecutable, ["dev"], { cwd: root, stdio: "inherit" }),
  spawn(
    process.execPath,
    ["--env-file-if-exists=.env", "--import", "tsx", "src/start.ts"],
    { cwd: root, stdio: "inherit" },
  ),
];

let stopping = false;

function stop(signal = "SIGTERM") {
  if (stopping) return;
  stopping = true;

  for (const child of children) {
    if (!child.killed) child.kill(signal);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => stop(signal));
}

for (const child of children) {
  child.on("error", (error) => {
    console.error(error.message);
    stop();
    process.exitCode = 1;
  });

  child.on("exit", (code, signal) => {
    if (!stopping) {
      process.exitCode = code ?? (signal ? 1 : 0);
      stop();
    }
  });
}
