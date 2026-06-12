/**
 * The in-page (courtesy) verifier mirrors the hard verifiers' negative-alg and
 * key-binding posture — crypto-adjacent surface, so the negative tests are
 * mandatory (CLAUDE.md): alg:none, alg substitution, tampered payload/signature,
 * padded segments, unknown kid, and swapped key material must ALL fail.
 *
 * Positive case: a REAL envelope signed by src/crypto must verify, and the
 * in-page SHA-256 / RFC 7638 thumbprint must agree with the server-side crypto.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/crypto/canonicalize.ts";
import { sha256Hex } from "../../src/crypto/hash.ts";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import { buildEnvelope, signEnvelope } from "../../src/evidence/envelope.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";
import {
  b64urlToBytes,
  bytesToB64url,
  computeOkpThumbprint,
  decodeEnvelope,
  parseCompactJws,
  sha256HexOfText,
  verifyEnvelopeSignature,
} from "../../web/js/inpage-verify.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
);

const signingKey = generateSigningKey();
const intent = {
  profile: "shariah-v0.1",
  merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
  amount: { value: 420, currency: "EUR" },
};
const envelope = buildEnvelope(intent, evaluate(intent, loadedPack.pack), loadedPack, fixedEnvelopeDeps);
const jws = signEnvelope(envelope, signingKey);
const jwks = buildJwks([signingKey.publicJwk]);

describe("positive path — a real signed envelope verifies in-page", () => {
  it("verifies the Ed25519 signature against the JWKS", async () => {
    const verdict = await verifyEnvelopeSignature(jws, jwks);
    expect(verdict).toEqual({ ok: true, kid: signingKey.kid });
  });

  it("decodes the envelope payload (deny + MAYSIR, as signed)", () => {
    const decoded = decodeEnvelope(jws) as Record<string, unknown>;
    expect(decoded["decision"]).toBe("deny");
    expect(decoded["reason_codes"]).toEqual(["MAYSIR"]);
    expect(decoded["rule_pack_hash"]).toBe(loadedPack.hash);
  });

  it("in-page SHA-256 agrees with the server-side hash over the canonical pack", async () => {
    const canonicalText = canonicalize(loadedPack.pack);
    expect(await sha256HexOfText(canonicalText)).toBe(loadedPack.hash);
    expect(await sha256HexOfText(canonicalText)).toBe(sha256Hex(canonicalText));
  });

  it("in-page RFC 7638 thumbprint agrees with the server-side kid", async () => {
    expect(await computeOkpThumbprint(signingKey.publicJwk.x)).toBe(signingKey.kid);
  });
});

describe("negative-alg and tamper cases — ALL must fail", () => {
  const [headerB64, payloadB64, signatureB64] = jws.split(".") as [string, string, string];

  function withHeader(header: Record<string, unknown>): string {
    const encoded = Buffer.from(JSON.stringify(header)).toString("base64url");
    return `${encoded}.${payloadB64}.${signatureB64}`;
  }

  it("alg:none is rejected BEFORE key material is touched", async () => {
    const verdict = await verifyEnvelopeSignature(withHeader({ alg: "none", kid: signingKey.kid }), jwks);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain('alg must be exactly "EdDSA"');
  });

  it("alg substitution (HS256) is rejected", async () => {
    const verdict = await verifyEnvelopeSignature(withHeader({ alg: "HS256", kid: signingKey.kid }), jwks);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain('alg must be exactly "EdDSA"');
  });

  it("crit header parameters are rejected", async () => {
    const verdict = await verifyEnvelopeSignature(
      withHeader({ alg: "EdDSA", kid: signingKey.kid, crit: ["exp"] }),
      jwks,
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("crit");
  });

  it("a tampered payload fails signature verification", async () => {
    const tamperedPayload = Buffer.from(
      JSON.stringify({ ...envelope, decision: "allow" }),
    ).toString("base64url");
    const verdict = await verifyEnvelopeSignature(`${headerB64}.${tamperedPayload}.${signatureB64}`, jwks);
    expect(verdict).toMatchObject({ ok: false, reason: "Ed25519 signature verification failed" });
  });

  it("a tampered signature fails", async () => {
    const sigBytes = b64urlToBytes(signatureB64);
    const flipped = Uint8Array.from(sigBytes);
    flipped[0] = (flipped[0] ?? 0) ^ 0xff;
    const verdict = await verifyEnvelopeSignature(
      `${headerB64}.${payloadB64}.${bytesToB64url(flipped)}`,
      jwks,
    );
    expect(verdict).toMatchObject({ ok: false, reason: "Ed25519 signature verification failed" });
  });

  it("a PADDED signature segment is rejected as malformed (no base64url malleability)", async () => {
    const verdict = await verifyEnvelopeSignature(`${headerB64}.${payloadB64}.${signatureB64}=`, jwks);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("base64url");
  });

  it("a non-3-segment string is rejected", async () => {
    const verdict = await verifyEnvelopeSignature(`${headerB64}.${payloadB64}`, jwks);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("exactly 3 segments");
  });

  it("an unknown kid is rejected (no fall-through to other keys)", async () => {
    const stranger = buildJwks([generateSigningKey().publicJwk]);
    const verdict = await verifyEnvelopeSignature(jws, stranger);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("not present in the JWKS");
  });

  it("swapped key material under the trusted kid is rejected (RFC 7638 binding)", async () => {
    const swapped = {
      keys: [{ ...signingKey.publicJwk, x: generateSigningKey().publicJwk.x }],
    };
    const verdict = await verifyEnvelopeSignature(jws, swapped);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("RFC 7638 thumbprint");
  });

  it("a non-Ed25519 JWKS entry is rejected before import", async () => {
    const wrongType = { keys: [{ ...signingKey.publicJwk, crv: "X25519" }] };
    const verdict = await verifyEnvelopeSignature(jws, wrongType);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("not an Ed25519 OKP key");
  });
});

describe("parse + encoding helpers", () => {
  it("parseCompactJws pins the header and round-trips the segments", () => {
    const parsed = parseCompactJws(jws);
    expect(parsed.header).toEqual({ alg: "EdDSA", kid: signingKey.kid });
    expect(`${parsed.headerB64}.${parsed.payloadB64}.${parsed.signatureB64}`).toBe(jws);
  });

  it("b64urlToBytes rejects padding and foreign characters", () => {
    expect(() => b64urlToBytes("abc=")).toThrow(/base64url/);
    expect(() => b64urlToBytes("a+b/c")).toThrow(/base64url/);
    expect(() => b64urlToBytes("")).toThrow(/base64url/);
  });

  it("bytesToB64url round-trips with b64urlToBytes", () => {
    const bytes = Uint8Array.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(b64urlToBytes(bytesToB64url(bytes))).toEqual(bytes);
  });
});
