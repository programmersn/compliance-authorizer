/**
 * Evidence store unit contract (ET14):
 *   - schema creation is idempotent (re-open never destroys data);
 *   - insert + read-back round-trips EVERY field, preserving the EXACT JWS bytes;
 *   - a duplicate decision_id is REJECTED (the store throws, never overwrites).
 *
 * The store is exercised against both an in-memory DB and a real file-backed DB
 * (a temp file) so the file path — the one boot uses — is covered too. The
 * backing engine is the built-in `node:sqlite` on this runtime.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  openEvidenceStore,
  type StoredDecision,
} from "../../src/store/evidence-store.ts";

// A representative stored decision. The evidence_artifact carries characters a
// naive store might mangle — base64url dots, a trailing '=', and a non-ASCII
// byte — so the round-trip proves byte-exact preservation, not just "a string".
const sampleArtifact =
  "eyJhbGciOiJFZERTQSJ9.eyJkZWNpc2lvbiI6ImRlbnkifQ.c2lnbmF0dXJlfHzDqXxffA==";

function sampleDecision(
  overrides: Partial<StoredDecision> = {},
): StoredDecision {
  return {
    decision_id: "ev-11111111-2222-4333-8444-555555555555",
    decision: "deny",
    reason_codes: ["MAYSIR"],
    rule_pack_id: "shariah",
    rule_pack_version: "0.1.1",
    rule_pack_hash:
      "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4",
    evaluator_version: "0.2.0",
    intent_hash:
      "9cc65d49e4ac6df696f26b41a95c8465f3556228eb249c54634980a5dc682c31",
    envelope_version: "0.1.0",
    decision_timestamp: "2026-06-04T12:00:00.000Z",
    evidence_artifact: sampleArtifact,
    ...overrides,
  };
}

const tempRoot = mkdtempSync(join(tmpdir(), "evidence-store-"));
afterAll(() => rmSync(tempRoot, { recursive: true, force: true }));

describe("evidence store — schema, round-trip, duplicate rejection", () => {
  it("creates its schema idempotently — re-opening the same file preserves rows", async () => {
    const dbPath = join(tempRoot, "idempotent.sqlite");

    const first = await openEvidenceStore(dbPath);
    const decision = sampleDecision();
    first.persist(decision);
    first.close();

    // Re-opening runs CREATE TABLE IF NOT EXISTS again — a no-op that must NOT
    // wipe the existing row (idempotent DDL, not a destructive migration).
    const second = await openEvidenceStore(dbPath);
    try {
      const readBack = second.read(decision.decision_id);
      expect(readBack).toBeDefined();
      expect(readBack?.decision).toBe("deny");
    } finally {
      second.close();
    }
  });

  it("round-trips every field and preserves the EXACT JWS bytes", async () => {
    const store = await openEvidenceStore(":memory:");
    try {
      const decision = sampleDecision({
        decision: "review",
        reason_codes: ["MIXED_REVENUE", "AGENT_SCOPE_EXCEEDED"],
      });
      store.persist(decision);

      const readBack = store.read(decision.decision_id);
      expect(readBack).toEqual(decision);
      // The signed artifact is the load-bearing column: assert byte-identity
      // explicitly, not just structural equality.
      expect(readBack?.evidence_artifact).toBe(sampleArtifact);
      expect(readBack?.reason_codes).toEqual([
        "MIXED_REVENUE",
        "AGENT_SCOPE_EXCEEDED",
      ]);
    } finally {
      store.close();
    }
  });

  it("returns undefined for an unknown decision_id", async () => {
    const store = await openEvidenceStore(":memory:");
    try {
      expect(store.read("ev-does-not-exist")).toBeUndefined();
    } finally {
      store.close();
    }
  });

  it("rejects a duplicate decision_id (the PK) — never a silent overwrite", async () => {
    const store = await openEvidenceStore(":memory:");
    try {
      const decision = sampleDecision();
      store.persist(decision);

      // Same PK, different payload: the store MUST throw (UNIQUE constraint), not
      // overwrite — a persisted decision is immutable evidence.
      expect(() =>
        store.persist(sampleDecision({ decision: "allow", reason_codes: [] })),
      ).toThrow();

      // The original row is intact: the failed second write changed nothing.
      const readBack = store.read(decision.decision_id);
      expect(readBack?.decision).toBe("deny");
    } finally {
      store.close();
    }
  });

  it("persists allow decisions with an empty reason_codes array", async () => {
    const store = await openEvidenceStore(":memory:");
    try {
      const decision = sampleDecision({
        decision_id: "ev-allow-0001",
        decision: "allow",
        reason_codes: [],
      });
      store.persist(decision);
      expect(store.read("ev-allow-0001")?.reason_codes).toEqual([]);
    } finally {
      store.close();
    }
  });
});
