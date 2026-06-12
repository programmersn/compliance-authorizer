/**
 * TWO-LAYER ENFORCEMENT (ET16 + ET17 — eng test-plan critical path #4):
 * credential scope ∩ rule pack, most-restrictive wins.
 *
 * Decisions are DETERMINISTIC — every case asserts the EXACT decision and the
 * EXACT reason_codes. The two HTTP categories the guards demand never blur:
 *
 *   - a DECISION (incl. a scope-exceeded DENY) → HTTP 200 + a SIGNED envelope;
 *   - an INVALID credential → 422 RFC 9457 problem+json, NEVER a signed
 *     envelope (error ≠ deny) — even when the rule pack would also deny.
 *
 * SYNTHETIC DATA ONLY: generic scenario labels (casino-hotel, mixed-revenue
 * ETF, subscription), generated throwaway keys, synthetic agent ids.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import { afterAll, describe, expect, it } from "vitest";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import { verifyCompact } from "../../src/crypto/jws.ts";
import { PROBLEM_CONTENT_TYPE } from "../../src/http/problem.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import type { RulePack } from "../../src/rules/pack-schema.ts";
import { buildServer } from "../../src/server.ts";
import { AGENT_SCOPE_EXCEEDED, decideIntent } from "../../src/vc/enforce.ts";
import { signAgentCredential } from "../../src/vc/mint.ts";
import { b64url, claimPayload, signClaim } from "./helpers.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
);
const issuerKey = generateSigningKey(); // signs CREDENTIALS (the agent's issuer)
const signingKey = generateSigningKey(); // signs EVIDENCE (the engine)

const app = buildServer({ loadedPacks: [loadedPack], signingKey });
afterAll(() => app.close());

/** Mint a synthetic credential scoping the agent to the given MCCs. */
const credentialFor = (...allowedMcc: string[]): string =>
  signAgentCredential(
    { agent_id: "synthetic-travel-agent", allowed_mcc: allowedMcc },
    issuerKey,
  );

/** A clean (pack-allow) hotel intent — generic synthetic label, mcc 7011. */
const hotelIntent = (overrides: Record<string, unknown> = {}) => ({
  profile: "shariah-v0.1",
  merchant: { name: "seaside-hotel", mcc: "7011", attributes: [] },
  amount: { value: 180, currency: "EUR" },
  ...overrides,
});

/** A pack-DENY intent: online betting, mcc 7995 (MAYSIR-MCC). */
const bettingIntent = (overrides: Record<string, unknown> = {}) => ({
  profile: "shariah-v0.1",
  merchant: { name: "online-betting-platform", mcc: "7995", attributes: [] },
  amount: { value: 50, currency: "EUR" },
  ...overrides,
});

/** A pack-REVIEW intent: mixed-revenue ETF, ratio 0.12 (MIXED_REVENUE). */
const etfIntent = (overrides: Record<string, unknown> = {}) => ({
  profile: "shariah-v0.1",
  merchant: { name: "mixed-revenue-etf", mcc: "6211", attributes: [] },
  amount: { value: 1000, currency: "USD" },
  screening: { mixed_revenue_ratio: 0.12 },
  ...overrides,
});

async function authorize(payload: Record<string, unknown>) {
  return app.inject({ method: "POST", url: "/authorize", payload });
}

describe("two-layer intersection matrix (EXACT decisions + reason_codes, pure decideIntent)", () => {
  it("pack-allow × scope-allow → allow, []", () => {
    const intent = hotelIntent({ agent_credential: credentialFor("7011") });
    expect(decideIntent(intent, loadedPack.pack)).toEqual({
      decision: "allow",
      reason_codes: [],
      matched_rules: [],
    });
  });

  it("pack-allow × scope-deny → DENY, [AGENT_SCOPE_EXCEEDED] (scope-deny beats pack-allow)", () => {
    const intent = hotelIntent({ agent_credential: credentialFor("5411") });
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual([AGENT_SCOPE_EXCEEDED]);
    // The scope layer is not a pack rule — matched_rules stays the pack's.
    expect(result.matched_rules).toEqual([]);
  });

  it("pack-deny × scope-allow → deny, [MAYSIR] (pack-deny beats scope-allow)", () => {
    const intent = bettingIntent({ agent_credential: credentialFor("7995") });
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR"]);
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual(["MAYSIR-MCC"]);
  });

  it("pack-deny × scope-deny → deny, [MAYSIR, AGENT_SCOPE_EXCEEDED] (both layers recorded)", () => {
    const intent = bettingIntent({ agent_credential: credentialFor("5411") });
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR", AGENT_SCOPE_EXCEEDED]);
  });

  it("pack-review × scope-allow → review, [MIXED_REVENUE] (review survives an in-scope MCC)", () => {
    const intent = etfIntent({ agent_credential: credentialFor("6211") });
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("review");
    expect(result.reason_codes).toEqual(["MIXED_REVENUE"]);
  });

  it("pack-review × scope-deny → DENY, [MIXED_REVENUE, AGENT_SCOPE_EXCEEDED] (deny > review)", () => {
    const intent = etfIntent({ agent_credential: credentialFor("5411") });
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MIXED_REVENUE", AGENT_SCOPE_EXCEEDED]);
    // The pack's review match is still recorded as the rule basis.
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual(["MIXED-REVENUE"]);
  });

  it("an ABSENT merchant.mcc never passes the scope screen (replay-only edge, §3 missing-field rule)", () => {
    // Unreachable through the API (the schema requires merchant.mcc) but MUST
    // be defined for replay determinism on foreign artifacts.
    const intent = {
      profile: "shariah-v0.1",
      merchant: { name: "no-mcc-merchant" },
      agent_credential: credentialFor("7011"),
    };
    const result = decideIntent(intent, loadedPack.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual([AGENT_SCOPE_EXCEEDED]);
  });

  it("reason_codes stay de-duplicated even if a pack rule already carries AGENT_SCOPE_EXCEEDED", () => {
    const pack: RulePack = structuredClone(loadedPack.pack);
    pack.rules = [
      {
        id: "TEST-ENGINE-CODE-COLLISION",
        reason_code: AGENT_SCOPE_EXCEEDED, // a pack may legally mint this string
        decision: "review",
        title: "test",
        description: "test",
        all_of: [{ field: "merchant.mcc", op: "equals", value: "7011" }],
        standards_ref: { status: "pending", note: "test" },
      },
    ];
    const intent = hotelIntent({ agent_credential: credentialFor("5411") });
    const result = decideIntent(intent, pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual([AGENT_SCOPE_EXCEEDED]); // once, not twice
  });
});

describe("credential-free intents behave EXACTLY as before (regression)", () => {
  it("decideIntent ≡ evaluate on arbitrary credential-free intents (property)", () => {
    const intentArbitrary = fc.record({
      profile: fc.constant("shariah-v0.1"),
      merchant: fc.record({
        name: fc.constantFrom("synthetic-merchant-a", "casino-hotel", "subscription-service"),
        mcc: fc.integer({ min: 0, max: 9999 }).map((n) => String(n).padStart(4, "0")),
        attributes: fc.uniqueArray(
          fc.constantFrom("gambling", "casino", "alcohol", "interest-bearing-credit", "speculative-derivatives", "retail"),
          { maxLength: 3 },
        ),
      }),
      amount: fc.record({
        value: fc.double({ min: 0, max: 100000, noNaN: true, noDefaultInfinity: true }),
        currency: fc.constantFrom("EUR", "USD", "GBP"),
      }),
    });
    fc.assert(
      fc.property(intentArbitrary, (intent) => {
        expect(decideIntent(intent, loadedPack.pack)).toEqual(
          evaluate(intent, loadedPack.pack),
        );
      }),
      { numRuns: 150 },
    );
  });

  it("HTTP: a credential-free deny is unchanged (deny, [MAYSIR], signed 200)", async () => {
    const response = await authorize(bettingIntent());
    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["decision"]).toBe("deny");
    expect(body["reason_codes"]).toEqual(["MAYSIR"]);
    expect(typeof body["evidence_artifact"]).toBe("string");
  });
});

describe("two-layer decisions are deterministic and scope-membership is a real property", () => {
  it("for-all scopes and intents: the combined decision IS most_restrictive(pack, scope) (property)", () => {
    const mccArbitrary = fc.integer({ min: 0, max: 9999 }).map((n) => String(n).padStart(4, "0"));
    const caseArbitrary = fc.record({
      intentMcc: mccArbitrary,
      allowedMcc: fc.uniqueArray(mccArbitrary, { minLength: 1, maxLength: 5 }),
      attributes: fc.uniqueArray(
        fc.constantFrom("gambling", "speculative-derivatives", "retail"),
        { maxLength: 2 },
      ),
    });
    fc.assert(
      fc.property(caseArbitrary, ({ intentMcc, allowedMcc, attributes }) => {
        const intent = {
          profile: "shariah-v0.1",
          merchant: { name: "synthetic-merchant", mcc: intentMcc, attributes },
          amount: { value: 10, currency: "EUR" },
          agent_credential: credentialFor(...allowedMcc),
        };
        const packResult = evaluate(intent, loadedPack.pack);
        const scopeAllows = allowedMcc.includes(intentMcc);
        const combined = decideIntent(intent, loadedPack.pack);

        // Independent expectation: most-restrictive under deny > review > allow.
        expect(combined.decision).toBe(scopeAllows ? packResult.decision : "deny");
        expect(combined.reason_codes).toEqual(
          scopeAllows
            ? packResult.reason_codes
            : [...packResult.reason_codes, AGENT_SCOPE_EXCEEDED],
        );
        expect(combined.matched_rules).toEqual(packResult.matched_rules);

        // Determinism: the same bytes decide identically, always.
        expect(decideIntent(intent, loadedPack.pack)).toEqual(combined);
      }),
      { numRuns: 120 },
    );
  });
});

describe("HTTP: a scope decision is a SIGNED 200; the envelope round-trips", () => {
  it("valid-scope allow → 200 allow with a verifiable signed envelope", async () => {
    const response = await authorize(
      hotelIntent({ agent_credential: credentialFor("7011") }),
    );
    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["decision"]).toBe("allow");
    expect(body["reason_codes"]).toEqual([]);
    const verified = verifyCompact(
      body["evidence_artifact"] as string,
      buildJwks([signingKey.publicJwk]),
    );
    expect((verified.payload as Record<string, unknown>)["decision"]).toBe("allow");
  });

  it("forbidden-scope → 200 SIGNED DENY, [AGENT_SCOPE_EXCEEDED] — a decision, never an error", async () => {
    const response = await authorize(
      hotelIntent({ agent_credential: credentialFor("5411") }),
    );
    expect(response.statusCode).toBe(200); // ← a scope-exceeded deny is a DECISION
    const body = response.json<Record<string, unknown>>();
    expect(body["decision"]).toBe("deny");
    expect(body["reason_codes"]).toEqual([AGENT_SCOPE_EXCEEDED]);
    expect(body["matched_rules"]).toEqual([]); // basis is the credential, not a pack rule

    // The envelope is SIGNED and carries the credentialed intent (intent_hash
    // covers the credential because it lives inside payment_intent).
    const verified = verifyCompact(
      body["evidence_artifact"] as string,
      buildJwks([signingKey.publicJwk]),
    );
    const envelope = verified.payload as Record<string, unknown>;
    expect(envelope["decision"]).toBe("deny");
    expect(envelope["reason_codes"]).toEqual([AGENT_SCOPE_EXCEEDED]);
    const citedIntent = envelope["payment_intent"] as Record<string, unknown>;
    expect(typeof citedIntent["agent_credential"]).toBe("string");
  });

  it("the full HTTP matrix matches the pure matrix (served == decided)", async () => {
    const cases: Array<{
      payload: Record<string, unknown>;
      decision: string;
      reason_codes: string[];
    }> = [
      { payload: bettingIntent({ agent_credential: credentialFor("7995") }), decision: "deny", reason_codes: ["MAYSIR"] },
      { payload: bettingIntent({ agent_credential: credentialFor("5411") }), decision: "deny", reason_codes: ["MAYSIR", AGENT_SCOPE_EXCEEDED] },
      { payload: etfIntent({ agent_credential: credentialFor("6211") }), decision: "review", reason_codes: ["MIXED_REVENUE"] },
      { payload: etfIntent({ agent_credential: credentialFor("5411") }), decision: "deny", reason_codes: ["MIXED_REVENUE", AGENT_SCOPE_EXCEEDED] },
    ];
    for (const expected of cases) {
      const response = await authorize(expected.payload);
      expect(response.statusCode).toBe(200);
      const body = response.json<Record<string, unknown>>();
      expect(body["decision"]).toBe(expected.decision);
      expect(body["reason_codes"]).toEqual(expected.reason_codes);
    }
  });
});

describe("HTTP: an INVALID credential is 422 problem+json, NEVER a signed envelope (error ≠ deny)", () => {
  /** Assert the full integration-failure shape for a credential defect. */
  async function expectCredentialProblem(
    payload: Record<string, unknown>,
    credentialError: string,
  ) {
    const response = await authorize(payload);
    expect(response.statusCode).toBe(422);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(422);
    expect(String(body["type"])).toContain("/invalid-agent-credential");
    expect(body["title"]).toBe("Invalid agent credential");
    expect(body["credential_error"]).toBe(credentialError);
    expect(body["detail"]).toContain("no evidence envelope");
    // The load-bearing assertions: a failure carries NO decision artifacts.
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
    expect(body).not.toHaveProperty("reason_codes");
  }

  it("tampered-signature credential → 422, signature_invalid, nothing signed", async () => {
    const genuine = credentialFor("7011");
    const [header, payload, signature] = genuine.split(".") as [string, string, string];
    const mid = Math.floor(signature.length / 2);
    const flipped = signature[mid] === "A" ? "B" : "A";
    const tampered = `${header}.${payload}.${signature.slice(0, mid)}${flipped}${signature.slice(mid + 1)}`;
    await expectCredentialProblem(
      hotelIntent({ agent_credential: tampered }),
      "signature_invalid",
    );
  });

  it('alg:"none" credential → 422, alg_rejected', async () => {
    const [, payload, signature] = credentialFor("7011").split(".") as [string, string, string];
    const noneHeader = b64url(JSON.stringify({ alg: "none", kid: issuerKey.did }));
    await expectCredentialProblem(
      hotelIntent({ agent_credential: `${noneHeader}.${payload}.${signature}` }),
      "alg_rejected",
    );
  });

  it("HS256-substitution credential → 422, alg_rejected", async () => {
    const [, payload, signature] = credentialFor("7011").split(".") as [string, string, string];
    const hsHeader = b64url(JSON.stringify({ alg: "HS256", kid: issuerKey.did }));
    await expectCredentialProblem(
      hotelIntent({ agent_credential: `${hsHeader}.${payload}.${signature}` }),
      "alg_rejected",
    );
  });

  it("not-a-JWS credential → 422, malformed", async () => {
    await expectCredentialProblem(
      hotelIntent({ agent_credential: "definitely-not-a-jws" }),
      "malformed",
    );
  });

  it("bad-did credential (kid is not a did:key) → 422, issuer_invalid", async () => {
    const credential = signClaim(claimPayload(issuerKey), issuerKey, {
      alg: "EdDSA",
      kid: issuerKey.kid, // a JWKS thumbprint, not a did:key
    });
    await expectCredentialProblem(
      hotelIntent({ agent_credential: credential }),
      "issuer_invalid",
    );
  });

  it("missing-scope credential → 422, payload_invalid", async () => {
    const claim = claimPayload(issuerKey);
    delete claim["scope"];
    await expectCredentialProblem(
      hotelIntent({ agent_credential: signClaim(claim, issuerKey) }),
      "payload_invalid",
    );
  });

  it("an invalid credential on a PACK-DENY intent is STILL 422 — admission precedes the decision, never blurs into it", async () => {
    await expectCredentialProblem(
      bettingIntent({ agent_credential: "definitely-not-a-jws" }),
      "malformed",
    );
  });

  it("an EMPTY-string credential fails at the schema (400 invalid-request-body), before the credential verifier", async () => {
    const response = await authorize(hotelIntent({ agent_credential: "" }));
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(String(body["type"])).toContain("invalid-request-body");
    expect(body).not.toHaveProperty("evidence_artifact");
  });
});
