import {
  createClient,
  type Client,
  type InStatement,
  type Transaction,
} from "@libsql/client";

import { toStorageError } from "../domain/errors.js";
import { readStorageConfig, type StorageConfig } from "./config.js";
import type {
  OperationalStore,
  SqlStatement,
  StoreTransaction,
} from "./operational-store.js";

const localWriteTails = new Map<string, Promise<void>>();

export function createLibSqlOperationalStore(
  config: StorageConfig = readStorageConfig(),
): OperationalStore {
  return new LibSqlOperationalStore(
    createClient({ ...config, timeout: 5_000 }),
    config.url.startsWith("file:") ? config.url : undefined,
  );
}

export class LibSqlOperationalStore implements OperationalStore {
  constructor(
    private readonly client: Client,
    private readonly localDatabaseKey?: string,
  ) {}

  async execute(statement: SqlStatement) {
    try {
      return await this.client.execute(toInStatement(statement));
    } catch (error) {
      throw toStorageError(error);
    }
  }

  async transaction<T>(fn: (tx: StoreTransaction) => Promise<T>): Promise<T> {
    const releaseLocalWrite = this.localDatabaseKey
      ? await acquireLocalWrite(this.localDatabaseKey)
      : undefined;
    let transaction: Transaction | undefined;
    try {
      transaction = await this.client.transaction("write");
      const activeTransaction = transaction;
      const handle: StoreTransaction = {
        execute: (statement) =>
          activeTransaction.execute(toInStatement(statement)),
        batch: (statements) =>
          activeTransaction.batch(statements.map(toInStatement)),
      };
      const value = await fn(handle);
      await transaction.commit();
      return value;
    } catch (error) {
      if (transaction && !transaction.closed) {
        try {
          await transaction.rollback();
        } catch {
          // The original error remains authoritative and is always redacted.
        }
      }
      throw toStorageError(error);
    } finally {
      transaction?.close();
      releaseLocalWrite?.();
    }
  }

  close(): void {
    this.client.close();
  }
}

async function acquireLocalWrite(key: string): Promise<() => void> {
  const previous = localWriteTails.get(key) ?? Promise.resolve();
  let releaseTurn = () => {};
  const turn = new Promise<void>((resolve) => {
    releaseTurn = resolve;
  });
  const tail = previous.then(() => turn);
  localWriteTails.set(key, tail);
  await previous;
  return () => {
    releaseTurn();
    if (localWriteTails.get(key) === tail) {
      void tail.then(() => localWriteTails.delete(key));
    }
  };
}

function toInStatement(statement: SqlStatement): InStatement {
  return {
    sql: statement.sql,
    ...(statement.args ? { args: statement.args } : {}),
  } as InStatement;
}
