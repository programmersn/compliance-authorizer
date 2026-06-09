/**
 * POST /authorize HTTP contract (ET6 + DT1 + DX9):
 *   - a DECISION — including DENY — is HTTP 200 with a signed envelope;
 *   - an INTEGRATION FAILURE is RFC 9457 problem+json and carries NO envelope,
 *     no decision, nothing signed. The two are structurally distinct.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { buildJwks, computeKid, generateSigningKey } from "../../src/crypto/keys.ts";
import { verifyCompact } from "../../src/crypto/jws.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { buildServer } from "../../src/server.ts";
import { PROBLEM_CONTENT_TYPE } from "../../src/http/problem.ts";
import {
  FIXED_TIMESTAMP,
  FIXED_UUID,
  fixedEnvelopeDeps,
} from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = generateSigningKey();

const app = buildServer({
  loadedPacks: [loadedPack],
  signingKey,
  envelopeDeps: fixedEnvelopeDeps,
});

afterAll(() => app.close());

const validIntent = {
  profile: "shariah-v0.1",
  merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
  amount: { value: 420, currency: "EUR" },
};

describe("decisions are ALWAYS 200 — read the body, not the status (DT1)", () => {
  it("DENY is HTTP 200 with a verifiable signed envelope", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: validIntent,
    });

    expect(response.statusCode).toBe(200); // ← a deny is a DECISION, not an error
    expect(response.headers["content-type"]).toContain("application/json");

    const body = response.json<Record<string, unknown>>();
    expect(body["decision"]).toBe("deny");
    expect(body["reason_codes"]).toEqual(["MAYSIR"]);
    expect(body["rule_pack_hash"]).toBe(loadedPack.hash);
    // The honesty marker and the response's own version are visible WITHOUT
    // decoding the JWS — machine consumers see "uncertified" at the top level.
    expect(body["rule_pack_status"]).toBe("uncertified");
    expect(body["envelope_version"]).toBe("0.1.0");
    expect(body["decision_id"]).toBe(`ev-${FIXED_UUID}`);
    expect(body["decision_timestamp"]).toBe(FIXED_TIMESTAMP);

    // The evidence artifact verifies and matches the response surface.
    const verified = verifyCompact(
      body["evidence_artifact"] as string,
      buildJwks([signingKey.publicJwk]),
    );
    const envelope = verified.payload as Record<string, unknown>;
    expect(envelope["decision"]).toBe("deny");
    expect(envelope["intent_hash"]).toBe(body["intent_hash"]);
    expect(envelope["scholar_signature_ref"]).toMatchObject({
      status: "uncertified",
      statement:
        "synthetic demo rule pack — not a fatwa / not certified / not production advice",
    });
  });

  it("ALLOW is HTTP 200", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        profile: "shariah-v0.1",
        merchant: { name: "seaside-hotel", mcc: "7011", attributes: [] },
        amount: { value: 180, currency: "EUR" },
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ decision: string }>().decision).toBe("allow");
  });

  it("REVIEW is HTTP 200 (mixed-revenue ETF scenario)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        profile: "shariah-v0.1",
        merchant: { name: "mixed-revenue-etf", mcc: "6211", attributes: [] },
        amount: { value: 1000, currency: "USD" },
        screening: { mixed_revenue_ratio: 0.12 },
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json<{ decision: string; reason_codes: string[] }>();
    expect(body.decision).toBe("review");
    expect(body.reason_codes).toEqual(["MIXED_REVENUE"]);
  });
});

describe("integration failures are problem+json and NEVER signed (error ≠ deny)", () => {
  // NOTE (coverage gap intentionally NOT closed): validationProblem() copies
  // AJV's params.allowedValues into an issue's `allowed_values` field, but AJV
  // only emits allowedValues for the `enum` keyword. PaymentIntentSchema has no
  // enum/literal-union field (every field is String/Number/Boolean with
  // pattern/min/max), so no externally-craftable intent reaches that sub-branch,
  // and validationProblem is not exported for direct unit testing. Closing it
  // would require either a schema change or a new export — both out of scope for
  // a tests-only change. The `issues` shape itself is asserted above.
  it("malformed intent (missing merchant) → 400 problem+json, NO envelope, NO decision", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { profile: "shariah-v0.1", amount: { value: 10, currency: "EUR" } },
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(400);
    expect(Array.isArray(body["issues"])).toBe(true);
    // The load-bearing assertions: a failure carries NO decision artifacts.
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
    expect(body["detail"]).toContain("no evidence envelope");
  });

  it("numeric mcc → 400 (no type coercion on a compliance API)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        ...validIntent,
        merchant: { ...validIntent.merchant, mcc: 7011 },
      },
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  it("unknown extra field → 400 (no silent stripping)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { ...validIntent, override_decision: "allow" },
    });
    expect(response.statusCode).toBe(400);
    const body = response.json<Record<string, unknown>>();
    expect(body).not.toHaveProperty("evidence_artifact");
  });

  it("unknown profile → 422 problem+json listing available profiles, NO envelope", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { ...validIntent, profile: "esg-v9.9" },
    });

    expect(response.statusCode).toBe(422);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

    const body = response.json<Record<string, unknown>>();
    expect(body["available_profiles"]).toEqual(["shariah-v0.1"]);
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
  });

  it("unknown route → 404 problem+json", async () => {
    const response = await app.inject({ method: "GET", url: "/nope" });
    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  // Framework-level request errors carry a 4xx statusCode but no .validation
  // array — they must surface as 4xx problem+json, never as a 500 "our fault",
  // and (as always) never anything signed.
  it("unparseable JSON body → 400 problem+json, never 500", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      headers: { "content-type": "application/json" },
      body: '{ "profile": ',
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(400);
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
  });

  it("empty JSON body → 400 problem+json, never 500", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      headers: { "content-type": "application/json" },
      body: "",
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  it("unsupported content-type → 415 problem+json, never 500", async () => {
    // (text/plain is natively parsed by Fastify and fails SCHEMA validation
    // with 400 instead — application/xml has no parser and hits the 415 path.)
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      headers: { "content-type": "application/xml" },
      body: "<intent/>",
    });
    expect(response.statusCode).toBe(415);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  it("body over the 1 MiB cap → 413 problem+json, never 500", async () => {
    const oversized = JSON.stringify({
      ...validIntent,
      merchant: { ...validIntent.merchant, name: "x".repeat(1_100_000) },
    });
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      headers: { "content-type": "application/json" },
      body: oversized,
    });
    expect(response.statusCode).toBe(413);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    expect(response.json<Record<string, unknown>>()).not.toHaveProperty(
      "evidence_artifact",
    );
  });
});

describe("unexpected handler errors are 500 problem+json — still error ≠ deny", () => {
  it("a handler throwing a plain Error → 500 problem+json, generic title, NOTHING signed", async () => {
    // A dedicated instance so the shared `app` stays clean. A plain Error has
    // no .validation and no 4xx .statusCode, so it falls through to the 500
    // branch — which must STILL be problem+json with no decision artifacts.
    const errorApp = buildServer({ loadedPacks: [loadedPack], signingKey });
    errorApp.get("/boom", () => {
      throw new Error("synthetic unexpected failure");
    });
    try {
      const response = await errorApp.inject({ method: "GET", url: "/boom" });
      expect(response.statusCode).toBe(500);
      expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

      const body = response.json<Record<string, unknown>>();
      expect(body["status"]).toBe(500);
      // Generic title — no internal error detail leaks to the caller.
      expect(body["title"]).toBe("Internal error");
      expect(body["detail"]).toContain("no evidence envelope");
      // The error ≠ deny invariant holds at 500 too: no decision certificate.
      expect(body).not.toHaveProperty("evidence_artifact");
      expect(body).not.toHaveProperty("decision");
    } finally {
      await errorApp.close();
    }
  });
});

describe("boot guards", () => {
  it("refuses duplicate rule-pack profiles instead of silently overwriting", () => {
    expect(() =>
      buildServer({ loadedPacks: [loadedPack, loadedPack], signingKey }),
    ).toThrow(/duplicate rule-pack profile/);
  });

  it("refuses duplicate rule-pack id/version even across distinct profiles", () => {
    // The duplicate-profile guard runs FIRST and trips on identical packs, so use a
    // DIFFERENT profile carrying the SAME id+version: the profile guard passes and
    // execution reaches the SEPARATE id/version guard (a distinct boot failure with
    // its own message). Two distinct profiles legitimately sharing an id/version is
    // exactly the case the id/version index in server.ts guards against.
    const second = {
      ...loadedPack,
      pack: { ...loadedPack.pack, profile: "shariah-v0.1-alt" },
    };
    expect(() =>
      buildServer({ loadedPacks: [loadedPack, second], signingKey }),
    ).toThrow(/duplicate rule-pack id\/version/);
  });

  it("refuses a published JWK whose kid is not its RFC 7638 thumbprint (fail closed, never serve swapped key material)", () => {
    const tamperedKey = { ...signingKey.publicJwk, kid: "not-a-thumbprint" };
    expect(() =>
      buildServer({
        loadedPacks: [loadedPack],
        signingKey,
        publishedKeys: [tamperedKey],
      }),
    ).toThrow(/not a valid Ed25519 signing key whose kid is its RFC 7638 thumbprint/);
  });

  it("refuses a published JWK that is not an Ed25519 OKP signing key (fail closed)", () => {
    // x/kid are internally consistent, but kty/crv/alg/use are wrong — the JWKS
    // endpoint would otherwise coerce them to the schema literals and publish a
    // non-Ed25519 key as if it were one. Boot must reject it.
    const wrongType = { ...signingKey.publicJwk, crv: "X25519" as "Ed25519" };
    expect(() =>
      buildServer({
        loadedPacks: [loadedPack],
        signingKey,
        publishedKeys: [wrongType],
      }),
    ).toThrow(/not a valid Ed25519 signing key/);
  });

  it("refuses a published JWK whose x is not an importable Ed25519 key (thumbprint-consistent but unusable)", () => {
    // kid IS the RFC 7638 thumbprint of this x, so the structural + thumbprint
    // guard passes — but x is not a valid Ed25519 public key, so an independent
    // verifier could never import it. Boot must reject it, not publish a dud key
    // that only fails downstream at verification time.
    const bogusX = "AAAA"; // not a 32-byte Ed25519 point — createPublicKey throws
    const unusable = {
      kty: "OKP" as const,
      crv: "Ed25519" as const,
      x: bogusX,
      kid: computeKid(bogusX),
      alg: "EdDSA" as const,
      use: "sig" as const,
    };
    expect(() =>
      buildServer({
        loadedPacks: [loadedPack],
        signingKey,
        // signer included, so this trips the import guard (which runs first),
        // not the signer-in-set guard below.
        publishedKeys: [unusable, signingKey.publicJwk],
      }),
    ).toThrow(/not an importable Ed25519 public key/);
  });

  it("refuses to boot when the live signer's key is NOT in publishedKeys (its decisions would fail the engine's own JWKS)", () => {
    // A rotation set that forgot the current signer. /authorize would sign with
    // `signingKey`, but JWKS + /verify resolve keys from publishedKeys — so every
    // freshly-issued envelope would fail this engine's own verification path.
    const otherKey = generateSigningKey().publicJwk; // valid, but not the signer
    expect(() =>
      buildServer({
        loadedPacks: [loadedPack],
        signingKey,
        publishedKeys: [otherKey],
      }),
    ).toThrow(/live signing key .* is not among publishedKeys/);
  });

  it("snapshots publishedKeys at boot — a post-boot mutation of the caller's object cannot change what JWKS serves", async () => {
    // Codex review #1: the boot guards validate publishedKeys once, but the routes
    // re-read the set on every request. buildServer freezes a PROJECTED snapshot at
    // boot, so a post-boot edit to the caller's object can never publish key
    // material the boot guards never validated (here, an unimportable `x`).
    const live = { ...signingKey.publicJwk }; // a mutable copy the caller still holds
    const originalX = live.x;
    const app = buildServer({ loadedPacks: [loadedPack], signingKey, publishedKeys: [live] });
    try {
      await app.ready();
      live.x = "tampered-after-boot"; // would be unimportable if the route read it live
      const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
      expect(response.statusCode).toBe(200);
      const body = response.json<{ keys: { kid: string; x: string }[] }>();
      // Exactly the boot-time bytes are served — the mutation did not leak through.
      expect(body.keys).toHaveLength(1);
      expect(body.keys[0]?.x).toBe(originalX);
    } finally {
      await app.close();
    }
  });
});
