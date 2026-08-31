import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  DemoScenarioSchema,
  type DemoJournal,
  type DemoScenario,
} from "./contracts.js";
import { createReadOnlyLibSqlOperationalStore } from "../db/libsql-operational-store.js";

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function withoutChecksum(
  journal: Omit<DemoJournal, "checksum">,
): Omit<DemoJournal, "checksum"> {
  return journal;
}

/** Revalidates the checksum when a parsed journal crosses another boundary. */
export function validateJournalIntegrity(journal: DemoJournal): void {
  DemoScenarioSchema.parse(journal.scenario);
  const { checksum, ...rest } = journal;
  if (checksum !== digest(withoutChecksum(rest)))
    throw new Error("DEMO_JOURNAL_TAMPERED");
}

export function demoRoot(
  root = resolve(process.cwd(), ".mastra", "demo-runs"),
): string {
  return resolve(root);
}

export function journalPath(root: string, demoRunId: string): string {
  if (!/^demo_[a-f0-9]{24}$/u.test(demoRunId))
    throw new Error("DEMO_RUN_ID_INVALID");
  return resolve(root, `${demoRunId}.json`);
}

export async function readJournal(
  root: string,
  demoRunId: string,
): Promise<DemoJournal | undefined> {
  try {
    const path = journalPath(root, demoRunId);
    const raw = JSON.parse(await readFile(path, "utf8")) as DemoJournal;
    validateJournalIntegrity(raw);
    return raw;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export async function writeJournal(
  root: string,
  current: DemoJournal | undefined,
  next: Omit<DemoJournal, "checksum" | "revision" | "updatedAt">,
): Promise<DemoJournal> {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const target = journalPath(root, next.demoRunId);
  const lockPath = `${target}.lock`;
  const lock = await acquireLock(lockPath);
  try {
    const authoritative = await readJournal(root, next.demoRunId);
    if (current) {
      if (
        !authoritative ||
        authoritative.revision !== current.revision ||
        authoritative.checksum !== current.checksum
      )
        throw new Error("DEMO_JOURNAL_CAS_CONFLICT");
    } else if (authoritative) {
      throw new Error("DEMO_JOURNAL_ALREADY_EXISTS");
    }
    const revision = (authoritative?.revision ?? 0) + 1;
    const updatedAt = new Date().toISOString();
    const value = { ...next, revision, updatedAt } as Omit<
      DemoJournal,
      "checksum"
    >;
    const journal = {
      ...value,
      checksum: digest(withoutChecksum(value)),
    } as DemoJournal;
    const temporary = resolve(
      dirname(target),
      `.${journal.demoRunId}.${revision}.${process.pid}.${randomSuffix()}.tmp`,
    );
    const staged = await open(temporary, "wx", 0o600);
    try {
      await staged.writeFile(`${JSON.stringify(journal)}\n`, "utf8");
      // A successful rename is only useful as a journal boundary when the
      // contents have reached the filesystem first.  This also keeps a crash
      // from publishing a zero-length temporary file as the next revision.
      await staged.sync();
    } finally {
      await staged.close();
    }
    await rename(temporary, target);
    return journal;
  } finally {
    await lock.close();
    await rm(lockPath, { force: true });
  }
}

export async function removeOwnedDatabase(
  root: string,
  journal: DemoJournal,
  options: Readonly<{
    /**
     * The runner owns the database schema and can therefore compare a logical
     * snapshot, which is stable across SQLite WAL checkpoints.  Keeping that
     * authority at the call site prevents this filesystem helper from treating
     * a changed main-db byte stream as a semantic mutation.
     */
    verifyPrecondition?: (
      resource: DemoJournal["resources"][number],
      databasePath: string,
    ) => Promise<boolean>;
  }> = {},
): Promise<void> {
  const expected = resolve(root, `${journal.demoRunId}.db`);
  if (resolve(journal.databasePath) !== expected)
    throw new Error("DEMO_CLEANUP_OWNERSHIP_DENIED");
  const resource = journal.resources.find(
    (candidate) =>
      candidate.kind === "local_database" &&
      candidate.ref === `local:${journal.demoRunId}`,
  );
  if (!resource || resource.ownership !== "created")
    throw new Error("DEMO_CLEANUP_OWNERSHIP_DENIED");
  // Absence of the primary file is never proof that its derived names are
  // ours. In particular, a failed reservation can leave a pending journal
  // beside a foreign `-wal`/`-shm`; deleting that sidecar would adopt data the
  // run never created. A completed cleanup returns before reaching this helper.
  if (!(await exists(expected)))
    throw new Error("DEMO_CLEANUP_PRECONDITION_FAILED");
  const valid = options.verifyPrecondition
    ? await options.verifyPrecondition(resource, expected)
    : (await resourceHash(expected)) === resource.expectedHash;
  if (!valid) throw new Error("DEMO_CLEANUP_PRECONDITION_FAILED");
  await rm(expected, { force: true });
  // SQLite sidecars are created only beside the owned database. They are
  // exact, derived paths—not a glob—and must not survive a claimed cleanup.
  await rm(`${expected}-wal`, { force: true });
  await rm(`${expected}-shm`, { force: true });
}

/** Removes only the separately journaled, closed observability database. */
export async function removeOwnedTraceDatabase(
  root: string,
  journal: DemoJournal,
): Promise<void> {
  const expected = resolve(root, `${journal.demoRunId}.trace.db`);
  if (resolve(journal.traceDatabasePath) !== expected)
    throw new Error("DEMO_TRACE_DATABASE_OWNERSHIP_DENIED");
  const resource = journal.resources.find(
    (candidate) =>
      candidate.kind === "local_trace_database" &&
      candidate.ref === `local-trace:${journal.demoRunId}`,
  );
  if (!resource || resource.ownership !== "created")
    throw new Error("DEMO_TRACE_DATABASE_OWNERSHIP_DENIED");
  // Mastra/libSQL can checkpoint the closed trace DB after the runner's last
  // semantic journal transition, changing physical SQLite bytes without a
  // logical trace mutation. Ownership remains bound by the exclusive-create
  // journal resource and exact derived path; require presence but never treat
  // a checkpoint as foreign data.
  if (!(await exists(expected)))
    throw new Error("DEMO_TRACE_DATABASE_PRECONDITION_FAILED");
  await rm(expected, { force: true });
  await rm(`${expected}-wal`, { force: true });
  await rm(`${expected}-shm`, { force: true });
}

/**
 * Reserve the exact DB path before libSQL can open it. A journal path is not
 * creation proof: only an exclusive create proves this run owns the resource.
 * Existing SQLite sidecars are foreign state too and are never adopted.
 */
export async function reserveOwnedDatabase(
  root: string,
  journal: DemoJournal,
): Promise<void> {
  const expected = resolve(root, `${journal.demoRunId}.db`);
  if (resolve(journal.databasePath) !== expected)
    throw new Error("DEMO_DATABASE_OWNERSHIP_DENIED");
  const claimed = journal.resources.some(
    (resource) =>
      resource.kind === "local_database" &&
      resource.ref === `local:${journal.demoRunId}` &&
      resource.ownership === "created" &&
      resource.expectedHash === `pending:${journal.demoRunId}`,
  );
  if (!claimed) throw new Error("DEMO_DATABASE_OWNERSHIP_DENIED");
  for (const path of [expected, `${expected}-wal`, `${expected}-shm`]) {
    if (await exists(path)) throw new Error("DEMO_DATABASE_ALREADY_EXISTS");
  }
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(expected, "wx", 0o600);
    if ((await exists(`${expected}-wal`)) || (await exists(`${expected}-shm`)))
      throw new Error("DEMO_DATABASE_ALREADY_EXISTS");
  } catch (error) {
    await handle?.close();
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      throw new Error("DEMO_DATABASE_ALREADY_EXISTS", { cause: error });
    throw error;
  }
  await handle.close();
}

/**
 * Reserves the run-owned observability database independently from the
 * operational database.  The trace store is never adopted from a prior run.
 */
export async function reserveOwnedTraceDatabase(
  root: string,
  journal: DemoJournal,
): Promise<void> {
  const expected = resolve(root, `${journal.demoRunId}.trace.db`);
  if (resolve(journal.traceDatabasePath) !== expected)
    throw new Error("DEMO_TRACE_DATABASE_OWNERSHIP_DENIED");
  const claimed = journal.resources.some(
    (resource) =>
      resource.kind === "local_trace_database" &&
      resource.ref === `local-trace:${journal.demoRunId}` &&
      resource.ownership === "created" &&
      resource.expectedHash === `pending:${journal.demoRunId}`,
  );
  if (!claimed) throw new Error("DEMO_TRACE_DATABASE_OWNERSHIP_DENIED");
  for (const path of [expected, `${expected}-wal`, `${expected}-shm`]) {
    if (await exists(path))
      throw new Error("DEMO_TRACE_DATABASE_ALREADY_EXISTS");
  }
  const handle = await open(expected, "wx", 0o600);
  await handle.close();
}

export async function resourceHash(path: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

/**
 * Validates the owned database before an observer is allowed to construct a
 * SQL client.  In particular this refuses a cleaned lifecycle, a path outside
 * the supplied demo root, symlinks/directories, pending reservations, and a
 * journal that no longer binds exactly one created local database.
 */
export async function assertDemoObservationPreconditions(
  root: string,
  journal: DemoJournal,
): Promise<DemoJournal["resources"][number]> {
  validateJournalIntegrity(journal);
  if (
    journal.state === "cleaned" ||
    journal.state === "cleaning" ||
    journal.state === "cleanup_failed" ||
    journal.state === "cleanup_blocked"
  )
    throw new Error("DEMO_CLEANUP_STATE_INVALID");
  if (journal.state !== "awaiting_approval" && journal.state !== "terminal")
    throw new Error("DEMO_SURFACE_STATE_INVALID");

  const expected = resolve(root, `${journal.demoRunId}.db`);
  if (resolve(journal.databasePath) !== expected)
    throw new Error("DEMO_DATABASE_OWNERSHIP_DENIED");
  const resources = journal.resources.filter(
    (resource) =>
      resource.kind === "local_database" &&
      resource.ref === `local:${journal.demoRunId}`,
  );
  const resource = resources[0];
  if (resources.length !== 1 || !resource || resource.ownership !== "created")
    throw new Error("DEMO_DATABASE_OWNERSHIP_DENIED");
  if (!/^[a-f0-9]{64}$/u.test(resource.expectedHash))
    throw new Error("DEMO_DATABASE_PRECONDITION_INVALID");

  let details: Awaited<ReturnType<typeof lstat>>;
  try {
    details = await lstat(expected);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      throw new Error("DEMO_DATABASE_PRECONDITION_FAILED", { cause: error });
    throw error;
  }
  if (!details.isFile()) throw new Error("DEMO_DATABASE_PRECONDITION_FAILED");
  return resource;
}

/**
 * Computes the same canonical, WAL-safe database snapshot used by the runner
 * and cleanup.  It is deliberately read-only: callers can validate a frozen
 * precondition without adopting, creating, or changing the owned DB.
 */
export async function semanticDatabaseHash(
  databasePath: string,
): Promise<string> {
  const store = createReadOnlyLibSqlOperationalStore({
    url: pathToFileURL(databasePath).href,
  });
  try {
    const tables = await store.execute({
      sql: `SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`,
    });
    const snapshot: Array<Readonly<{ name: string; rows: readonly string[] }>> =
      [];
    for (const table of tables.rows) {
      const name = table.name;
      if (typeof name !== "string")
        throw new Error("DEMO_DATABASE_SCHEMA_INVALID");
      const rows = await store.execute({
        sql: `SELECT * FROM ${quoteIdentifier(name)}`,
      });
      snapshot.push({
        name,
        rows: rows.rows.map(canonicalRow).sort(),
      });
    }
    return createHash("sha256").update(JSON.stringify(snapshot)).digest("hex");
  } finally {
    store.close();
  }
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function canonicalRow(row: Record<string, unknown>): string {
  return JSON.stringify(
    Object.entries(row)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [key, canonicalValue(value)]),
  );
}

function canonicalValue(value: unknown): unknown {
  if (value instanceof Uint8Array)
    return { bytes: Buffer.from(value).toString("base64") };
  if (typeof value === "bigint") return { bigint: value.toString() };
  return value;
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

const lockStaleAfterMs = 30_000;

async function acquireLock(path: string) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const lock = await open(path, "wx", 0o600);
      try {
        await lock.writeFile(
          JSON.stringify({
            pid: process.pid,
            host: hostname(),
            createdAt: new Date().toISOString(),
            fence: randomSuffix(),
          }),
          "utf8",
        );
        await lock.sync();
        return lock;
      } catch (error) {
        await lock.close();
        await rm(path, { force: true });
        throw error;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await reclaimStaleLock(path);
      await new Promise<void>((done) => setTimeout(done, 5));
    }
  }
  throw new Error("DEMO_JOURNAL_LOCK_TIMEOUT");
}

/**
 * A process that still owns a lock is never reclaimed merely because it is
 * slow.  We only retire a sufficiently old, local lock when its recorded PID
 * is definitely gone.  Invalid/remote lock records intentionally remain
 * fail-closed: an operator can inspect them rather than racing another host.
 */
async function reclaimStaleLock(path: string): Promise<void> {
  let details: Awaited<ReturnType<typeof stat>>;
  try {
    details = await stat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (Date.now() - details.mtimeMs < lockStaleAfterMs) return;
  let owner: { pid?: unknown; host?: unknown };
  try {
    owner = JSON.parse(await readFile(path, "utf8")) as {
      pid?: unknown;
      host?: unknown;
    };
  } catch {
    return;
  }
  if (
    owner.host !== hostname() ||
    typeof owner.pid !== "number" ||
    !Number.isSafeInteger(owner.pid) ||
    owner.pid <= 0 ||
    processExists(owner.pid)
  )
    return;
  // Re-read the metadata just before unlinking.  It is not a distributed lock
  // service, but this fence prevents reclaiming a lock that changed while it
  // was being inspected on the local filesystem.
  try {
    const latest = await stat(path);
    if (latest.ino !== details.ino || latest.mtimeMs !== details.mtimeMs)
      return;
    await rm(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function randomSuffix(): string {
  return createHash("sha256")
    .update(`${process.pid}:${Date.now()}:${Math.random()}`)
    .digest("hex")
    .slice(0, 12);
}

export function newJournal(
  input: Readonly<{
    root: string;
    demoRunId: string;
    scenario: DemoScenario;
    runKeyHash: string;
  }>,
): Omit<DemoJournal, "checksum" | "revision" | "updatedAt"> {
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    demoRunId: input.demoRunId,
    scenario: input.scenario,
    mode: "mock",
    runKeyHash: input.runKeyHash,
    state: "prepared",
    createdAt: now,
    databasePath: resolve(input.root, `${input.demoRunId}.db`),
    traceDatabasePath: resolve(input.root, `${input.demoRunId}.trace.db`),
    resources: [],
  };
}
