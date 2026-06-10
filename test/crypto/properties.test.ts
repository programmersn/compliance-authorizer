/**
 * Property-based tests (ET12, fast-check): the two independent JCS
 * implementations must agree on arbitrary JSON, hashing must be key-order
 * invariant, and EVERY synthetic intent must produce evidence the standalone
 * verifier accepts.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { canonicalize, CanonicalizationError } from "../../src/crypto/canonicalize.ts";
import { sha256Hex } from "../../src/crypto/hash.ts";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import { buildEnvelope, signEnvelope } from "../../src/evidence/envelope.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePack } from "../../src/rules/loader.ts";
import { jcsCanonicalize, verifyEvidence } from "../../verifier/verify.mjs";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const packText = readFileSync(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
  "utf8",
);
const loadedPack = loadRulePack(packText);
const packDocument: unknown = JSON.parse(packText);

/**
 * Deep key-order shuffle: rebuild every object with reversed key insertion
 * order. Built on null-prototype objects so a generated "__proto__" key stays
 * an own property instead of silently setting the prototype.
 */
function reverseKeyOrder(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseKeyOrder);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const result = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(record).reverse()) {
      result[key] = reverseKeyOrder(record[key]);
    }
    return result;
  }
  return value;
}

describe("fast-check global config (reproducible property runs)", () => {
  it("a global seed is pinned so a CI counterexample replays locally", () => {
    expect(fc.readConfigureGlobal()?.seed).toBeDefined();
  });
});

describe("dual JCS implementations agree (sign-side TS vs verifier-side JS)", () => {
  it("canonicalize === jcsCanonicalize for arbitrary JSON values (agree on output AND on rejection)", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        // The two independent implementations must agree on EVERY input — both
        // on the canonical bytes AND on REJECTING an input (e.g. invalid Unicode
        // such as a lone surrogate, which RFC 8785 §3.2.2.2 requires terminating
        // on). A divergence in EITHER direction is a forgery/interop bug.
        let tsForm: string | undefined;
        let tsThrew = false;
        try {
          tsForm = canonicalize(value);
        } catch {
          tsThrew = true;
        }
        let jsForm: string | undefined;
        let jsThrew = false;
        try {
          jsForm = jcsCanonicalize(value);
        } catch {
          jsThrew = true;
        }
        expect(jsThrew).toBe(tsThrew);
        if (!tsThrew) expect(tsForm).toBe(jsForm);
      }),
      { numRuns: 500 },
    );
  });

  it("canonical form is invariant under key reordering (both implementations)", () => {
    // Wrap each generated value in a record with two fixed-named keys so EVERY
    // run embeds a ≥2-key object — otherwise a primitive/array draw would carry
    // no keys to reorder and the property would pass trivially.
    const multiKey = fc.record({ beta: fc.jsonValue(), alpha: fc.jsonValue() });
    fc.assert(
      fc.property(multiKey, (value) => {
        const shuffled = reverseKeyOrder(value);
        expect(canonicalize(shuffled)).toBe(canonicalize(value));
        expect(jcsCanonicalize(shuffled)).toBe(jcsCanonicalize(value));
      }),
      { numRuns: 300 },
    );
  });

  it("canonical form is invariant under pretty-print round-trips", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const reparsed: unknown = JSON.parse(JSON.stringify(value, null, 3));
        expect(canonicalize(reparsed)).toBe(canonicalize(value));
      }),
      { numRuns: 300 },
    );
  });

  it("therefore: sha256(JCS(x)) is key-order and whitespace independent", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const viaShuffle = sha256Hex(canonicalize(reverseKeyOrder(value)));
        const viaPretty = sha256Hex(
          canonicalize(JSON.parse(JSON.stringify(value, null, 2))),
        );
        expect(viaShuffle).toBe(sha256Hex(canonicalize(value)));
        expect(viaPretty).toBe(sha256Hex(canonicalize(value)));
      }),
      { numRuns: 200 },
    );
  });
});

describe("RFC 8785 §3.2.2.2: both JCS implementations REJECT lone surrogates identically", () => {
  // fc.jsonValue() does not synthesize lone surrogates (empirically 0 in tens of
  // thousands of draws), so the agreement property above never exercises the
  // both-throw branch from random input — these explicit cases pin that BOTH
  // independent canonicalizers reject invalid Unicode, rather than silently
  // escaping it as \udXXX the way a strict external verifier would refuse.
  it.each([
    ["lone high surrogate value", String.fromCharCode(0xd800)],
    ["lone low surrogate value", String.fromCharCode(0xdc00)],
    ["lone surrogate in a longer string", `tip ${String.fromCharCode(0xd834)}!`],
    ["lone surrogate in an object KEY", { [String.fromCharCode(0xd800)]: 1 }],
    ["lone surrogate nested in an array", ["ok", { note: String.fromCharCode(0xdc00) }]],
  ])("both reject %s", (_label, value) => {
    expect(() => canonicalize(value)).toThrow(CanonicalizationError);
    expect(() => jcsCanonicalize(value)).toThrow(/lone UTF-16 surrogate/);
  });

  it("both ACCEPT a valid surrogate pair, byte-identically (only LONE surrogates are rejected)", () => {
    const value = { label: String.fromCharCode(0xd83d, 0xde00), note: "ok" }; // 😀
    expect(canonicalize(value)).toBe(jcsCanonicalize(value));
  });
});

// --- synthetic intent arbitrary (SYNTHETIC DATA ONLY — generic tokens) -----

const attributeToken = fc.constantFrom(
  "gambling",
  "casino",
  "alcohol",
  "interest-bearing-credit",
  "speculative-derivatives",
  "family-friendly",
  "retail",
);

const intentArbitrary = fc.record(
  {
    profile: fc.constant("shariah-v0.1"),
    merchant: fc.record(
      {
        name: fc.constantFrom(
          "synthetic-merchant-a",
          "synthetic-merchant-b",
          "casino-hotel",
          "mixed-revenue-etf",
          "subscription-service",
        ),
        mcc: fc
          .integer({ min: 0, max: 9999 })
          .map((n) => String(n).padStart(4, "0")),
        attributes: fc.uniqueArray(attributeToken, { maxLength: 4 }),
      },
      { requiredKeys: ["name", "mcc"] },
    ),
    amount: fc.record({
      value: fc
        .double({ min: 0, max: 1_000_000, noNaN: true, noDefaultInfinity: true })
        .map((n) => Math.round(n * 100) / 100),
      currency: fc.constantFrom("EUR", "USD", "GBP", "AED"),
    }),
    recurring: fc.boolean(),
    screening: fc.record(
      {
        mixed_revenue_ratio: fc
          .double({ min: 0, max: 1, noNaN: true })
          .map((n) => Math.round(n * 1000) / 1000),
      },
      { requiredKeys: [] },
    ),
  },
  { requiredKeys: ["profile", "merchant", "amount"] },
);


describe("for-all synthetic intents: evidence signs and offline-verifies", () => {
  const key = generateSigningKey();
  const jwks = buildJwks([key.publicJwk]);

  it("sign → standalone offline verify passes for every generated intent", () => {
    fc.assert(
      fc.property(intentArbitrary, (intent) => {
        const evaluation = evaluate(intent, loadedPack.pack);
        expect(["allow", "review", "deny"]).toContain(evaluation.decision);

        const envelope = buildEnvelope(
          intent,
          evaluation,
          loadedPack,
          fixedEnvelopeDeps,
        );
        const jws = signEnvelope(envelope, key);
        const result = verifyEvidence({ jws, jwks, pack: packDocument });
        expect(result.ok).toBe(true);
        expect(result.envelope?.["decision"]).toBe(evaluation.decision);
        expect(result.envelope?.["intent_hash"]).toBe(
          sha256Hex(jcsCanonicalize(intent)),
        );
      }),
      { numRuns: 150 },
    );
  });

  it("decisions are deterministic: evaluating twice yields deep-equal results", () => {
    fc.assert(
      fc.property(intentArbitrary, (intent) => {
        expect(evaluate(intent, loadedPack.pack)).toEqual(
          evaluate(intent, loadedPack.pack),
        );
      }),
      { numRuns: 150 },
    );
  });

  it('any intent whose attributes include "gambling" is denied with MAYSIR', () => {
    // Force "gambling" into the attribute set (deduped, "gambling" first) so all
    // numRuns exercise the deny path — no fc.pre discards, no trivially-passing runs.
    const gamblingIntent = intentArbitrary.map((intent) => ({
      ...intent,
      merchant: {
        ...intent.merchant,
        attributes: [
          "gambling",
          ...(intent.merchant.attributes ?? []).filter((a) => a !== "gambling"),
        ],
      },
    }));
    fc.assert(
      fc.property(gamblingIntent, (intent) => {
        expect(intent.merchant.attributes).toContain("gambling");
        const evaluation = evaluate(intent, loadedPack.pack);
        expect(evaluation.decision).toBe("deny");
        expect(evaluation.reason_codes).toContain("MAYSIR");
      }),
      { numRuns: 80 },
    );
  });
});
