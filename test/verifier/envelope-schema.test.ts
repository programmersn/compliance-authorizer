/**
 * Strict envelope-schema enforcement in the offline verifier (P2 hardening).
 *
 * verifier/verify.mjs is the contract the rendered decision certificate (W3
 * viewer) is built against, so its envelope-shape check enforces the EXACT v0.1
 * shape — the precise field set (no unknown fields), every field's type, and
 * every format — not just required-field presence. A signed-but-malformed
 * envelope is only producible by the key holder, so this is robustness against a
 * buggy signer, never an outsider-reachable hole.
 *
 * Each case below builds a GENUINE envelope, mutates exactly one thing, and
 * RE-SIGNS, so the signature and canonical-form checks both pass and the
 * envelope-shape gate is the first (and only) failure — the schema is what
 * catches it, not a broken signature.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import {
  buildEnvelope,
  signEnvelope,
  UNCERTIFIED_SCHOLAR_REF,
} from "../../src/evidence/envelope.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { verifyEvidence } from "../../verifier/verify.mjs";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loaded = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = generateSigningKey();

// The canonical deny scenario (a casino-hotel whose attributes flag gambling →
// MAYSIR-ATTR). A generic synthetic label; no real merchant or PII.
const denyIntent = {
  profile: "shariah-v0.1",
  merchant: {
    name: "casino-hotel",
    mcc: "7011",
    country: "GB",
    attributes: ["casino", "gambling"],
  },
  amount: { value: 389.99, currency: "GBP" },
};

// A byte-reproducible genuine deny envelope (fixed clock + uuid + fixed signer).
const genuineEnvelope = buildEnvelope(
  denyIntent,
  evaluate(denyIntent, loaded.pack),
  loaded,
  fixedEnvelopeDeps,
);

/** Sign {genuine ± overrides} and verify it (no pack — shape is checked first). */
function verifyWithOverrides(overrides: Record<string, unknown>) {
  const jws = signEnvelope({ ...genuineEnvelope, ...overrides }, signingKey);
  return verifyEvidence({ jws, jwks: buildJwks([signingKey.publicJwk]) });
}

type Result = ReturnType<typeof verifyWithOverrides>;

/**
 * Assert the artifact was rejected AT the strict envelope-shape gate, with a
 * detail naming the offending field — and that every check before it PASSED, so
 * the rejection is the schema and not a broken signature / non-canonical form.
 */
function expectShapeFailure(result: Result, detailSubstring: string) {
  expect(result.ok).toBe(false);
  expect(result.checks.find((c) => c.id === "signature")?.ok).toBe(true);
  expect(result.checks.find((c) => c.id === "canonical-form")?.ok).toBe(true);
  const shape = result.checks.find((c) => c.id === "envelope-shape");
  expect(shape?.ok).toBe(false);
  expect(shape?.detail).toContain(detailSubstring);
}

describe("verifier strict envelope schema: genuine envelopes still pass", () => {
  it("a genuine deny envelope passes the strict envelope-shape check", () => {
    const result = verifyWithOverrides({});
    expect(result.ok).toBe(true);
    const shape = result.checks.find((c) => c.id === "envelope-shape");
    expect(shape?.ok).toBe(true);
    expect(shape?.detail).toContain("v0.1 schema valid");
  });

  it("an allow-shaped envelope with EMPTY reason_codes/matched_rules passes (no false non-empty requirement)", () => {
    // The schema must accept the natural allow shape — matched nothing, so both
    // arrays are empty. intent_hash is unchanged, so the artifact stays valid.
    const result = verifyWithOverrides({
      decision: "allow",
      reason_codes: [],
      matched_rules: [],
    });
    expect(result.ok).toBe(true);
    expect(result.checks.find((c) => c.id === "envelope-shape")?.ok).toBe(true);
  });
});

describe("verifier strict envelope schema: structural rejections", () => {
  it("rejects an UNKNOWN top-level field", () => {
    expectShapeFailure(verifyWithOverrides({ surprise: true }), "unknown field(s): surprise");
  });

  it("rejects an envelope_version other than 0.1.0 (exact pin, not just semver)", () => {
    expectShapeFailure(verifyWithOverrides({ envelope_version: "0.2.0" }), 'handles "0.1.0"');
  });

  it("rejects a payment_intent that is not a JSON object", () => {
    expectShapeFailure(
      verifyWithOverrides({ payment_intent: "not-an-object" }),
      "payment_intent is not a JSON object",
    );
  });
});

describe("verifier strict envelope schema: format rejections", () => {
  it("rejects a decision_id that is not ev-<uuid>", () => {
    expectShapeFailure(verifyWithOverrides({ decision_id: "ev-not-a-uuid" }), "decision_id");
  });

  it("rejects a decision_timestamp that is not ISO-8601", () => {
    expectShapeFailure(
      verifyWithOverrides({ decision_timestamp: "2026-06-04 12:00" }),
      "decision_timestamp",
    );
  });

  it("rejects a pattern-shaped but IMPOSSIBLE timestamp (round-trip check beats a naive regex)", () => {
    // Matches \d{4}-\d{2}-\d{2}T...Z yet is not a real instant; only the exact
    // Date.toISOString round-trip rejects it.
    expectShapeFailure(
      verifyWithOverrides({ decision_timestamp: "2026-13-45T99:99:99.999Z" }),
      "decision_timestamp",
    );
  });

  it("rejects an UPPERCASE (non-lowercase) sha256 rule_pack_hash", () => {
    expectShapeFailure(
      verifyWithOverrides({ rule_pack_hash: genuineEnvelope.rule_pack_hash.toUpperCase() }),
      "rule_pack_hash",
    );
  });

  it("rejects an intent_hash that is not 64 lowercase hex", () => {
    expectShapeFailure(verifyWithOverrides({ intent_hash: "deadbeef" }), "intent_hash");
  });

  it("rejects a non-semver evaluator_version", () => {
    expectShapeFailure(verifyWithOverrides({ evaluator_version: "0.1" }), "evaluator_version");
  });
});

describe("verifier strict envelope schema: array shapes", () => {
  it("rejects reason_codes that is not an array", () => {
    expectShapeFailure(verifyWithOverrides({ reason_codes: "MAYSIR" }), "reason_codes is not an array");
  });

  it("rejects a malformed (lowercase) reason code element", () => {
    expectShapeFailure(verifyWithOverrides({ reason_codes: ["maysir"] }), "reason_codes[0]");
  });

  it("rejects matched_rules that is not an array", () => {
    expectShapeFailure(verifyWithOverrides({ matched_rules: {} }), "matched_rules is not an array");
  });

  it("rejects a matched_rules entry carrying an UNKNOWN field", () => {
    const rule = { ...genuineEnvelope.matched_rules[0], surprise: 1 };
    expectShapeFailure(
      verifyWithOverrides({ matched_rules: [rule] }),
      "matched_rules[0] has unexpected or missing fields",
    );
  });

  it('rejects a matched_rules entry whose decision is "allow" (only deny/review may match)', () => {
    const rule = { ...genuineEnvelope.matched_rules[0], decision: "allow" };
    expectShapeFailure(
      verifyWithOverrides({ matched_rules: [rule] }),
      'matched_rules[0].decision is not "deny" or "review"',
    );
  });

  it("rejects a matched_rules entry whose standards_ref.status is not pending", () => {
    const rule = {
      ...genuineEnvelope.matched_rules[0],
      standards_ref: { status: "certified", note: "x" },
    };
    expectShapeFailure(
      verifyWithOverrides({ matched_rules: [rule] }),
      "matched_rules[0].standards_ref.status",
    );
  });
});

describe("verifier strict envelope schema: scholar_signature_ref (UNCERTIFIED specimen)", () => {
  it("rejects a scholar_signature_ref with an UNKNOWN field", () => {
    expectShapeFailure(
      verifyWithOverrides({
        scholar_signature_ref: { ...UNCERTIFIED_SCHOLAR_REF, surprise: 1 },
      }),
      "scholar_signature_ref has unexpected or missing fields",
    );
  });

  it("rejects a non-null scholar_did (a certified-looking forgery on a v0.1 envelope)", () => {
    expectShapeFailure(
      verifyWithOverrides({
        scholar_signature_ref: { ...UNCERTIFIED_SCHOLAR_REF, scholar_did: "did:key:zABC" },
      }),
      "scholar_signature_ref.scholar_did must be null",
    );
  });

  it('rejects a scholar_signature_ref.status other than "uncertified"', () => {
    expectShapeFailure(
      verifyWithOverrides({
        scholar_signature_ref: { ...UNCERTIFIED_SCHOLAR_REF, status: "certified" },
      }),
      "scholar_signature_ref.status",
    );
  });
});

describe("verifier strict envelope schema: it gates BEFORE the hash recomputations", () => {
  it("a malformed intent_hash fails at envelope-shape, never reaching the intent-hash check", () => {
    const result = verifyWithOverrides({ intent_hash: "deadbeef" });
    expect(result.ok).toBe(false);
    expect(result.checks.find((c) => c.id === "envelope-shape")?.ok).toBe(false);
    // Short-circuited at step 6: the (later) intent-hash check never ran.
    expect(result.checks.find((c) => c.id === "intent-hash")).toBeUndefined();
  });
});
