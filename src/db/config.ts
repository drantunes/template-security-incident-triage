import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export type StorageConfig = Readonly<{
  url: string;
  authToken?: string;
}>;

export function resolveStorageUrl(
  value: string,
  projectDirectory = process.env.INIT_CWD ?? process.cwd(),
): string {
  if (!value.startsWith("file:")) return value;

  const filePath = value.slice("file:".length);
  if (!filePath || filePath.startsWith("//") || isAbsolute(filePath)) {
    return value;
  }

  return pathToFileURL(resolve(projectDirectory, filePath)).href;
}

export function readStorageConfig(
  environment: NodeJS.ProcessEnv = process.env,
  projectDirectory = environment.INIT_CWD ?? process.cwd(),
): StorageConfig {
  const url = resolveStorageUrl(
    environment.MASTRA_STORAGE_URL ?? "file:./mastra.db",
    projectDirectory,
  );
  const authToken = environment.MASTRA_STORAGE_AUTH_TOKEN;

  return Object.freeze({
    url,
    ...(authToken ? { authToken } : {}),
  });
}
