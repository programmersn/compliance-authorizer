/**
 * Evidence store (ET14) — public surface. The persistence leg of POST /authorize:
 * one signed decision in → one observational row out, behind an engine-agnostic
 * SQLite seam (built-in `node:sqlite`, documented `better-sqlite3` fallback).
 *
 * See `evidence-store.ts` for the error ≠ deny storage-boundary contract.
 */
export {
  openEvidenceStore,
  type EvidenceStore,
  type StoredDecision,
} from "./evidence-store.ts";
export type { SqliteDriver, SqliteStatement, SqlValue } from "./sqlite.ts";
export { openSqlite } from "./sqlite.ts";
