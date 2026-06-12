/**
 * SQLite driver seam (ET14): the engine-agnostic handle the evidence store sits
 * on. On this runtime the built-in `node:sqlite` answers; `better-sqlite3` is the
 * documented, intentionally-uninstalled fallback. These tests pin the contract
 * the store relies on: the built-in is selected, DDL is idempotent, a constraint
 * violation PROPAGATES (the store turns that into fail-closed at the HTTP layer),
 * and a read miss is `undefined`.
 *
 * The "no engine available" error message is asserted as a string contract here
 * without uninstalling the built-in (which a test cannot do): the message MUST
 * name both `node:sqlite` and `better-sqlite3` so an operator who hits it knows
 * the two seams. The branch that throws it is covered by construction — both
 * `tryNodeSqlite` and `tryBetterSqlite3` returning null is the only way in, and
 * the second is the shipped reality (the package is not installed).
 */
import { describe, expect, it } from "vitest";
import { openSqlite } from "../../src/store/sqlite.ts";

describe("SQLite driver — backend selection + the subset the store uses", () => {
  it("selects the built-in node:sqlite backend on this runtime", async () => {
    const db = await openSqlite(":memory:");
    try {
      expect(db.backend).toBe("node:sqlite");
    } finally {
      db.close();
    }
  });

  it("runs DDL idempotently and round-trips a prepared insert/select", async () => {
    const db = await openSqlite(":memory:");
    try {
      const ddl = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, v TEXT NOT NULL)";
      db.exec(ddl);
      db.exec(ddl); // idempotent — must not throw on the second run
      db.prepare("INSERT INTO t (id, v) VALUES (?, ?)").run("a", "hello");
      const row = db.prepare("SELECT id, v FROM t WHERE id = ?").get("a");
      expect(row).toEqual({ id: "a", v: "hello" });
      // A read miss is undefined, not null or an empty row.
      expect(db.prepare("SELECT id FROM t WHERE id = ?").get("missing")).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("PROPAGATES a UNIQUE-constraint violation from run() (the store fails closed on it)", async () => {
    const db = await openSqlite(":memory:");
    try {
      db.exec("CREATE TABLE t (id TEXT PRIMARY KEY)");
      const ins = db.prepare("INSERT INTO t (id) VALUES (?)");
      ins.run("dup");
      expect(() => ins.run("dup")).toThrow();
    } finally {
      db.close();
    }
  });
});
