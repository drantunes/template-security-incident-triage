import { LibSQLStore } from "@mastra/libsql";

import { readStorageConfig, type StorageConfig } from "../db/config.js";

export function createMastraStorage(
  config: StorageConfig = readStorageConfig(),
) {
  return new LibSQLStore({
    id: "security-incident-storage",
    ...config,
  });
}

export const storage = createMastraStorage();
