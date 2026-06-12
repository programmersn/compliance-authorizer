/**
 * Evidence store (ET14): one row per ISSUED decision, persisted AFTER the
 * envelope is signed at POST /authorize. The store is OBSERVATIONAL — it never
 * shapes the response, never touches the envelope bytes, and never participates
 * in the decision. With no store wired, the API behaves identically (the persist
 * hook is optional in the route).
 *
 * Guards this module upholds (all from CLAUDE.md):
 *
 *   - **Synthetic data only, by construction.** Every column is derived from a
 *     signed evidence envelope over a synthetic payment intent; no PII or real
 *     card/customer data can reach here.
 *   - **error ≠ deny at the STORAGE boundary.** A write failure must never let a
 *     signed envelope reach the caller alongside an error. The route persists
 *     BEFORE returning the body and lets a thrown store error propagate to the
 *     problem handler → 500 problem+json, NO envelope. This module therefore
 *     simply throws on failure (e.g. a duplicate decision_id); it never swallows.
 *   - **Determinism is untouched.** Storage reads the already-built envelope; it
 *     cannot alter the decision, the reason codes, or the JWS bytes.
 */
import type { SqliteDriver } from "./sqlite.ts";
import { openSqlite } from "./sqlite.ts";

/**
 * One persisted decision. Mirrors the top-level evidence-envelope fields plus
 * the full signed artifact. `reason_codes` is stored as a JSON array string; the
 * `evidence_artifact` is the verbatim JWS-compact string — the bytes a verifier
 * checks, preserved EXACTLY (no re-encoding, no canonicalization on the way in).
 */
export interface StoredDecision {
  decision_id: string;
  decision: "allow" | "deny" | "review";
  reason_codes: readonly string[];
  rule_pack_id: string;
  rule_pack_version: string;
  rule_pack_hash: string;
  evaluator_version: string;
  intent_hash: string;
  envelope_version: string;
  decision_timestamp: string;
  /** The full JWS-compact evidence artifact — stored byte-for-byte. */
  evidence_artifact: string;
}

/**
 * The persistence port the route depends on. Kept minimal and synchronous: the
 * persist hook runs inline on the request path AFTER signing, so a failure can
 * fail the request closed (no envelope leaks past a storage error).
 */
export interface EvidenceStore {
  /**
   * Persist one issued decision. THROWS on any write failure — including a
   * duplicate `decision_id` (the PK) — so the caller can fail the request
   * closed. Never returns a partial success.
   */
  persist(decision: StoredDecision): void;
  /**
   * Read a stored decision back by id, or `undefined` if absent. Present for the
   * round-trip/read-back path (and tests); the request path only writes.
   */
  read(decisionId: string): StoredDecision | undefined;
  /** Release the underlying database handle. */
  close(): void;
}

const CREATE_TABLE = `
  CREATE TABLE IF NOT EXISTS decisions (
    decision_id        TEXT PRIMARY KEY,
    decision           TEXT NOT NULL,
    reason_codes       TEXT NOT NULL,
    rule_pack_id       TEXT NOT NULL,
    rule_pack_version  TEXT NOT NULL,
    rule_pack_hash     TEXT NOT NULL,
    evaluator_version  TEXT NOT NULL,
    intent_hash        TEXT NOT NULL,
    envelope_version   TEXT NOT NULL,
    decision_timestamp TEXT NOT NULL,
    evidence_artifact  TEXT NOT NULL
  ) STRICT;
`;

const INSERT = `
  INSERT INTO decisions (
    decision_id, decision, reason_codes, rule_pack_id, rule_pack_version,
    rule_pack_hash, evaluator_version, intent_hash, envelope_version,
    decision_timestamp, evidence_artifact
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`;

const SELECT_BY_ID = `
  SELECT decision_id, decision, reason_codes, rule_pack_id, rule_pack_version,
         rule_pack_hash, evaluator_version, intent_hash, envelope_version,
         decision_timestamp, evidence_artifact
  FROM decisions WHERE decision_id = ?;
`;

/**
 * A {@link EvidenceStore} backed by SQLite. Construct it with {@link openEvidenceStore}.
 * Schema creation is idempotent (`CREATE TABLE IF NOT EXISTS` + `STRICT`), so
 * re-opening an existing DB is a no-op, never a destructive migration.
 */
class SqliteEvidenceStore implements EvidenceStore {
  readonly #db: SqliteDriver;

  constructor(db: SqliteDriver) {
    this.#db = db;
    // Idempotent: safe on a fresh file AND on an already-initialized one.
    this.#db.exec(CREATE_TABLE);
  }

  /** Which SQLite backend answered — for the boot log only. */
  get backend(): SqliteDriver["backend"] {
    return this.#db.backend;
  }

  persist(decision: StoredDecision): void {
    // A duplicate decision_id raises a UNIQUE-constraint error here; we let it
    // propagate. The route treats ANY throw as a storage failure and fails the
    // request closed (500 problem+json, no envelope) — never a partial write.
    this.#db
      .prepare(INSERT)
      .run(
        decision.decision_id,
        decision.decision,
        JSON.stringify(decision.reason_codes),
        decision.rule_pack_id,
        decision.rule_pack_version,
        decision.rule_pack_hash,
        decision.evaluator_version,
        decision.intent_hash,
        decision.envelope_version,
        decision.decision_timestamp,
        decision.evidence_artifact,
      );
  }

  read(decisionId: string): StoredDecision | undefined {
    const row = this.#db.prepare(SELECT_BY_ID).get(decisionId);
    if (row === undefined) return undefined;
    return rowToDecision(row);
  }

  close(): void {
    this.#db.close();
  }
}

/**
 * Open a file-backed (or `":memory:"`) SQLite evidence store and ensure its
 * schema exists. Resolves the SQLite engine via {@link openSqlite} (built-in
 * first, documented fallback second), so an environment with no SQLite engine
 * fails CLOSED here with one instructive error — the store is never silently
 * a no-op.
 */
export async function openEvidenceStore(path: string): Promise<EvidenceStore> {
  const db = await openSqlite(path);
  return new SqliteEvidenceStore(db);
}

/** Narrow a raw SQLite row back into a {@link StoredDecision}. */
function rowToDecision(row: Record<string, unknown>): StoredDecision {
  const reasonCodesRaw = row["reason_codes"];
  const reasonCodes: string[] =
    typeof reasonCodesRaw === "string"
      ? (JSON.parse(reasonCodesRaw) as string[])
      : [];
  return {
    decision_id: String(row["decision_id"]),
    decision: row["decision"] as StoredDecision["decision"],
    reason_codes: reasonCodes,
    rule_pack_id: String(row["rule_pack_id"]),
    rule_pack_version: String(row["rule_pack_version"]),
    rule_pack_hash: String(row["rule_pack_hash"]),
    evaluator_version: String(row["evaluator_version"]),
    intent_hash: String(row["intent_hash"]),
    envelope_version: String(row["envelope_version"]),
    decision_timestamp: String(row["decision_timestamp"]),
    evidence_artifact: String(row["evidence_artifact"]),
  };
}
