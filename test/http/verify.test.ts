/**
 * POST /verify HTTP contract — the error ≠ deny guard for the VERIFICATION path:
 *
 *   - A WELL-FORMED request is ALWAYS HTTP 200 with a verification RESULT.
 *     valid:true  == cryptographically authentic; valid:false == well-formed
 *     request but an INAUTHENTIC artifact (bad signature, tampered payload,
 *     alg != EdDSA, ...). valid:false is STILL 200 — a verdict, never a 4xx.
 *     The trap this file guards against: 4xx-ing on "signature invalid" is the
 *     same category error as error=deny.
 *   - A MALFORMED request (missing/empty/non-string evidence_artifact, unknown
 *     extra field) is an INTEGRATION FAILURE → 400 problem+json, NO verdict.
 *
 * Route-isolated: the route plugin is registered on a FRESH Fastify() instance
 * (NOT buildServer()) so this file never imports a sibling route module. The
 * AJV options are pinned to MATCH production (server.ts): no coercion, no
 * stripping — otherwise a bare Fastify() would coerce 123→"123" and strip the
 * unknown field, masking the two 400 cases below.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { canonicalize } from "../../src/crypto/canonicalize.ts";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import {
  buildEnvelope,
  signEnvelope,
  UNCERTIFIED_SCHOLAR_REF,
} from "../../src/evidence/envelope.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import {
  PROBLEM_CONTENT_TYPE,
  registerProblemHandling,
} from "../../src/http/problem.ts";
import { verifyRoute } from "../../src/routes/verify.ts";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loaded = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = generateSigningKey();

// The canonical deny scenario: a casino-hotel whose merchant attributes flag
// gambling → MAYSIR-ATTR matches → decision "deny" (a generic synthetic label).
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

// A GENUINE, byte-reproducible deny artifact (fixed clock+uuid + fixed signer).
const genuineArtifact = signEnvelope(
  buildEnvelope(denyIntent, evaluate(denyIntent, loaded.pack), loaded, fixedEnvelopeDeps),
  signingKey,
);

const b64url = (value: object): string =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

const [genuineHeader, genuinePayload, genuineSignature] =
  genuineArtifact.split(".") as [string, string, string];

// (b) corrupted signature: flip a char in the MIDDLE of the signature segment.
// (Tail base64url bits can alias to the same decoded bytes — the middle cannot.)
const sigMid = Math.floor(genuineSignature.length / 2);
const flipped = genuineSignature[sigMid] === "A" ? "B" : "A";
const corruptedSigArtifact =
  `${genuineHeader}.${genuinePayload}.${genuineSignature.slice(0, sigMid)}` +
  `${flipped}${genuineSignature.slice(sigMid + 1)}`;

// (c) decision flipped deny→allow, payload re-canonicalized (RFC 8785 key
// order preserved), but NOT re-signed: the original signature no longer covers
// these payload bytes, so the signature check fails (tamper-evident).
const tamperedEnvelope = {
  ...(JSON.parse(
    Buffer.from(genuinePayload, "base64url").toString("utf8"),
  ) as Record<string, unknown>),
  decision: "allow",
};
// Re-canonicalize with the real RFC 8785 canonicalizer so the payload differs
// from the genuine one ONLY in `decision` and is itself well-formed canonical
// JSON — the signature mismatch (verifier step 4) is the sole defect, checked
// BEFORE canonical-form, so it is unambiguously what fails.
const tamperedPayload = Buffer.from(
  canonicalize(tamperedEnvelope),
  "utf8",
).toString("base64url");
const flippedDecisionArtifact = `${genuineHeader}.${tamperedPayload}.${genuineSignature}`;

// (d) alg:"none": a well-formed 3-segment artifact whose header pins no real
// algorithm. Rejected at the alg-pinning check, BEFORE any key is touched.
const algNoneArtifact = `${b64url({ alg: "none", kid: signingKey.kid })}.${genuinePayload}.${genuineSignature}`;

function buildApp() {
  const app = Fastify({
    ajv: {
      customOptions: {
        coerceTypes: false,
        removeAdditional: false,
        useDefaults: false,
      },
    },
  });
  registerProblemHandling(app);
  void app.register(verifyRoute, {
    publishedKeys: [signingKey.publicJwk],
    packsByIdVersion: new Map([
      [`${loaded.pack.id}/${loaded.pack.version}`, loaded],
    ]),
  });
  return app;
}

const app = buildApp();
afterAll(() => app.close());

async function verify(evidence_artifact: unknown) {
  return app.inject({
    method: "POST",
    url: "/verify",
    payload: { evidence_artifact } as Record<string, unknown>,
  });
}

describe("a well-formed request is ALWAYS 200 — valid:false is a verdict, not a 4xx", () => {
  it("(a) genuine artifact → 200 valid:true, decision deny, pack resolved, uncertified", async () => {
    const response = await verify(genuineArtifact);

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");

    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(true);
    expect(body["decision"]).toBe("deny");
    expect(body["rule_pack_id"]).toBe("shariah");
    expect(body["rule_pack_version"]).toBe("0.1.0");
    expect(body["rule_pack_resolved"]).toBe(true);
    // UNCERTIFIED is unavoidable on every served surface, and the honesty
    // wording is byte-exact with the verbatim contract.
    expect(body["uncertified"]).toBe(true);
    expect(body["disclaimer"]).toBe(UNCERTIFIED_SCHOLAR_REF.statement);
    expect(body["disclaimer"]).toContain("not a fatwa / not certified / not production advice");
    // The forward-projection copy stays future-conditional.
    expect(body["certification_note"]).toContain("would");
    // Every offline check passed — the result mirrors the standalone verifier.
    expect(Array.isArray(body["checks"])).toBe(true);
    expect((body["checks"] as { ok: boolean }[]).every((c) => c.ok)).toBe(true);
    // The issuer fingerprint is surfaced (did:key + kid).
    expect(body["issuer"]).toMatchObject({ kid: signingKey.kid });
  });

  it("(b) corrupted signature → 200 valid:false (NOT a 4xx)", async () => {
    const response = await verify(corruptedSigArtifact);

    expect(response.statusCode).toBe(200); // ← the trap: this is NOT a 400
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(false);
    // Failed at the signature check specifically.
    const checks = body["checks"] as { id: string; ok: boolean }[];
    expect(checks.find((c) => c.id === "signature")?.ok).toBe(false);
    // UNCERTIFIED holds even on an inauthentic verdict.
    expect(body["uncertified"]).toBe(true);
  });

  it("(c) decision flipped deny→allow, re-canonicalized but NOT re-signed → 200 valid:false", async () => {
    const response = await verify(flippedDecisionArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(false);
    // Tamper-evident: the signature no longer covers the altered payload.
    const checks = body["checks"] as { id: string; ok: boolean }[];
    expect(checks.find((c) => c.id === "signature")?.ok).toBe(false);
  });

  it("(d) alg:\"none\" artifact → 200 valid:false (alg rejected before key material)", async () => {
    const response = await verify(algNoneArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(false);
    // Rejected at the alg-pinning check — only "EdDSA" is accepted.
    const checks = body["checks"] as { id: string; ok: boolean }[];
    expect(checks.find((c) => c.id === "alg-pinned")?.ok).toBe(false);
  });
});

describe("a MALFORMED request is 400 problem+json with NO verdict (error ≠ deny)", () => {
  it("missing evidence_artifact { } → 400 problem+json, no verdict", async () => {
    const response = await app.inject({ method: "POST", url: "/verify", payload: {} });

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(400);
    // A failure carries NO verdict fields.
    expect(body).not.toHaveProperty("valid");
    expect(body).not.toHaveProperty("decision");
    expect(body).not.toHaveProperty("checks");
  });

  it("empty evidence_artifact \"\" → 400 (minLength:1)", async () => {
    const response = await verify("");

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    expect(response.json<Record<string, unknown>>()).not.toHaveProperty("valid");
  });

  it("non-string evidence_artifact 123 → 400 (no coercion on a compliance API)", async () => {
    const response = await verify(123);

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    expect(response.json<Record<string, unknown>>()).not.toHaveProperty("valid");
  });

  it("unknown extra field → 400 (no silent stripping)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/verify",
      payload: { evidence_artifact: genuineArtifact, replay: true },
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(body).not.toHaveProperty("valid");
    expect(body).not.toHaveProperty("decision");
  });
});
