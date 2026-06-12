/**
 * SQLite driver seam (ET14): the evidence store talks to SQLite through the
 * narrow {@link SqliteDriver} surface below, so the store never imports a
 * concrete engine directly. Two backends satisfy it, tried in order:
 *
 *   1. `node:sqlite` (the built-in `DatabaseSync`) — the DEFAULT. On Node it is
 *      an experimental built-in (it emits an ExperimentalWarning on first use),
 *      so no dependency is added to ship it. This is what dev / start / tests run.
 *   2. `better-sqlite3` — a DOCUMENTED FALLBACK SEAM, deliberately NOT installed.
 *      If the built-in is ever unavailable (an older runtime, a build that
 *      compiled it out), {@link openSqlite} attempts to load it; absent the
 *      package, boot fails with one instructive error naming BOTH options. The
 *      fallback is a seam, not a silently-added dependency: adding it is an
 *      explicit, reviewable `npm install better-sqlite3`.
 *
 * Both engines expose `prepare(sql).run(...)/.get(...)` and `exec(sql)`; this
 * module normalizes the tiny shape the store uses and hides which one answered.
 */

/** A prepared statement — the subset the evidence store calls. */
export interface SqliteStatement {
  /** Execute a write (INSERT/DDL). A constraint violation THROWS — callers rely on this. */
  run(...params: SqlValue[]): unknown;
  /** Read at most one row, or `undefined` when nothing matches. */
  get(...params: SqlValue[]): Record<string, unknown> | undefined;
}

/** The narrow database handle the store depends on (engine-agnostic). */
export interface SqliteDriver {
  /** Run one or more statements with no bound params (DDL: CREATE TABLE …). */
  exec(sql: string): void;
  /** Compile a parameterized statement for repeated `run`/`get`. */
  prepare(sql: string): SqliteStatement;
  /** Release the underlying file handle. */
  close(): void;
  /** Which backend answered — surfaced for the boot log / diagnostics only. */
  readonly backend: "node:sqlite" | "better-sqlite3";
}

/** Bindable SQLite value types the store uses (text columns + the PK string). */
export type SqlValue = string | number | null;

/**
 * The built-in `node:sqlite` `DatabaseSync` shape we consume. Declared locally
 * (rather than importing its types) so this file type-checks even on a toolchain
 * whose @types/node predates the module — the import itself is dynamic.
 */
interface NodeDatabaseSyncCtor {
  new (
    path: string,
    options?: { readOnly?: boolean },
  ): {
    exec(sql: string): void;
    prepare(sql: string): {
      run(...params: SqlValue[]): unknown;
      get(...params: SqlValue[]): unknown;
    };
    close(): void;
  };
}

/** The `better-sqlite3` default-export shape we would consume if it were present. */
interface BetterSqlite3Ctor {
  new (path: string): {
    exec(sql: string): void;
    prepare(sql: string): {
      run(...params: SqlValue[]): unknown;
      get(...params: SqlValue[]): unknown;
    };
    close(): void;
  };
}

/**
 * Open a SQLite database at `path` (use `":memory:"` for an ephemeral DB), trying
 * the built-in first and the documented fallback second.
 *
 * Throws ONE instructive error naming both engines if neither can be loaded —
 * the store fails CLOSED at boot rather than silently degrading persistence.
 */
export async function openSqlite(path: string): Promise<SqliteDriver> {
  const builtin = await tryNodeSqlite(path);
  if (builtin) return builtin;

  const fallback = await tryBetterSqlite3(path);
  if (fallback) return fallback;

  throw new Error(
    "no SQLite engine available for the evidence store: the built-in " +
      "`node:sqlite` could not be loaded on this runtime, and the documented " +
      "fallback `better-sqlite3` is not installed. Run on Node >= 22.6 (where " +
      "`node:sqlite` ships built-in), or add the fallback explicitly with " +
      "`npm install better-sqlite3`. (The fallback is an intentional seam, not a " +
      "bundled dependency.) The store can also be left DISABLED — the API serves " +
      "decisions unchanged without it.",
  );
}

/** Attempt the built-in `node:sqlite`; return `null` (not throw) if it is unavailable. */
async function tryNodeSqlite(path: string): Promise<SqliteDriver | null> {
  let DatabaseSync: NodeDatabaseSyncCtor;
  try {
    // Dynamic import: `node:sqlite` is an experimental built-in, so importing it
    // statically would couple the whole module graph to its presence. A runtime
    // without it (or with it compiled out) lands in catch → we fall through.
    const mod = (await import("node:sqlite")) as {
      DatabaseSync?: NodeDatabaseSyncCtor;
    };
    if (typeof mod.DatabaseSync !== "function") return null;
    DatabaseSync = mod.DatabaseSync;
  } catch {
    return null;
  }
  const db = new DatabaseSync(path);
  return wrapDriver(db, "node:sqlite");
}

/** Attempt the `better-sqlite3` fallback; return `null` if it is not installed. */
async function tryBetterSqlite3(path: string): Promise<SqliteDriver | null> {
  let Database: BetterSqlite3Ctor;
  try {
    // `better-sqlite3` is intentionally NOT a dependency, so the package (and its
    // types) is absent in the shipped configuration. The specifier is held in a
    // runtime variable so the compiler does not try to RESOLVE it statically — a
    // bare `import("better-sqlite3")` would be a typecheck error precisely because
    // the package is uninstalled. At runtime this import throws
    // ERR_MODULE_NOT_FOUND, which we swallow; openSqlite() then raises the single
    // naming-both-options error. Installing the package (an explicit, reviewable
    // `npm install better-sqlite3`) is all it takes to light up this seam.
    const specifier = "better-sqlite3";
    const mod = (await import(specifier)) as {
      default?: BetterSqlite3Ctor;
    };
    if (typeof mod.default !== "function") return null;
    Database = mod.default;
  } catch {
    return null;
  }
  const db = new Database(path);
  return wrapDriver(db, "better-sqlite3");
}

/**
 * Normalize a concrete engine handle to {@link SqliteDriver}. Both engines'
 * `get()` return a plain row object (or undefined); we narrow it to the shape
 * the store reads. A constraint violation in `run()` is left to PROPAGATE — the
 * store turns a duplicate `decision_id` into a thrown error by design.
 */
function wrapDriver(
  db: {
    exec(sql: string): void;
    prepare(sql: string): {
      run(...params: SqlValue[]): unknown;
      get(...params: SqlValue[]): unknown;
    };
    close(): void;
  },
  backend: SqliteDriver["backend"],
): SqliteDriver {
  return {
    backend,
    exec: (sql) => {
      db.exec(sql);
    },
    prepare: (sql) => {
      const stmt = db.prepare(sql);
      return {
        run: (...params) => stmt.run(...params),
        get: (...params) => {
          const row = stmt.get(...params);
          // node:sqlite returns a null-prototype object; spread into a plain one
          // so consumers (and `in`/property reads) behave normally. undefined ⇒
          // no row.
          return row == null
            ? undefined
            : { ...(row as Record<string, unknown>) };
        },
      };
    },
    close: () => {
      db.close();
    },
  };
}
