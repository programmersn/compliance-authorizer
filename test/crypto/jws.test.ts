/**
 * JWS sign/verify (ET11): round-trip, jose-as-oracle cross-checks, and the
 * negative-alg matrix. Every negative test EXECUTES the real attack (a
 * correctly-built malicious token), not a malformed string.
 */
import { createHmac } from "node:crypto";
import { CompactSign, compactVerify, calculateJwkThumbprint, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import { canonicalBytes } from "../../src/crypto/canonicalize.ts";
import {
  EVIDENCE_JWS_ALG,
  JwsError,
  signCompact,
  verifyCompact,
} from "../../src/crypto/jws.ts";
import {
  base58btcDecode,
  base58btcEncode,
  buildJwks,
  computeKid,
  didKeyFromRawPublicKey,
  exportPrivateJwk,
  generateSigningKey,
  importPrivateJwk,
  rawPublicKeyFromDidKey,
} from "../../src/crypto/keys.ts";
import { verifyEvidence } from "../../verifier/verify.mjs";

const b64url = (data: Uint8Array | string): string =>
  Buffer.from(data).toString("base64url");

const samplePayload = (): Uint8Array =>
  canonicalBytes({ decision: "deny", reason_codes: ["MAYSIR"], n: 1 });

describe("JWS round-trip (node:crypto sign → node:crypto verify)", () => {
  it("signs and verifies, returning the exact payload bytes", () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const jws = signCompact(payload, key);
    const verified = verifyCompact(jws, buildJwks([key.publicJwk]));
    expect(Buffer.from(verified.payloadBytes).equals(Buffer.from(payload))).toBe(true);
    expect(verified.header.alg).toBe(EVIDENCE_JWS_ALG);
    expect(verified.header.kid).toBe(key.kid);
  });

  it("restores a key from its private JWK and produces identical signatures", () => {
    const key = generateSigningKey();
    const restored = importPrivateJwk(exportPrivateJwk(key));
    const payload = samplePayload();
    // Ed25519 is deterministic: same key + same payload → same JWS.
    expect(signCompact(payload, restored)).toBe(signCompact(payload, key));
    expect(restored.kid).toBe(key.kid);
    expect(restored.did).toBe(key.did);
  });
});

describe("jose as independent oracle (cross-implementation checks)", () => {
  it("a token we sign verifies under jose", async () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const jws = signCompact(payload, key);
    const joseKey = await importJWK({ ...key.publicJwk }, "EdDSA");
    const { payload: josePayload, protectedHeader } = await compactVerify(jws, joseKey, {
      algorithms: ["EdDSA"],
    });
    expect(Buffer.from(josePayload).equals(Buffer.from(payload))).toBe(true);
    expect(protectedHeader.kid).toBe(key.kid);
  });

  it("a token jose signs verifies under our verifier", async () => {
    const key = generateSigningKey();
    const payload = samplePayload();
    const josePrivate = await importJWK({ ...exportPrivateJwk(key) }, "EdDSA");
    const jws = await new CompactSign(payload)
      .setProtectedHeader({ alg: "EdDSA", kid: key.kid })
      .sign(josePrivate);
    const verified = verifyCompact(jws, buildJwks([key.publicJwk]));
    expect(Buffer.from(verified.payloadBytes).equals(Buffer.from(payload))).toBe(true);
  });

  it("our RFC 7638 kid matches jose's thumbprint calculation", async () => {
    const key = generateSigningKey();
    const joseThumbprint = await calculateJwkThumbprint(
      { kty: "OKP", crv: "Ed25519", x: key.publicJwk.x },
      "sha256",
    );
    expect(key.kid).toBe(joseThumbprint);
    expect(computeKid(key.publicJwk.x)).toBe(joseThumbprint);
  });
});

describe("negative-alg matrix — real attacks, all rejected", () => {
  it('rejects alg:"none" (unsigned token smuggling)', () => {
    const key = generateSigningKey();
    const header = b64url(JSON.stringify({ alg: "none", kid: key.kid }));
    const payload = b64url(samplePayload());
    const attack = `${header}.${payload}.`;
    expect(() => verifyCompact(attack, buildJwks([key.publicJwk]))).toThrow(JwsError);
    try {
      verifyCompact(`${header}.${payload}.${b64url("sig")}`, buildJwks([key.publicJwk]));
      expect.unreachable("alg:none must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("alg_rejected");
    }
  });

  it("rejects HS256 substitution (HMAC keyed with the PUBLIC key bytes)", () => {
    // The classic alg-confusion attack: the attacker knows the Ed25519 public
    // key, mints an HS256 token using those bytes as the HMAC secret, and hopes
    // the verifier dispatches on the token's alg header.
    const key = generateSigningKey();
    const publicKeyBytes = Buffer.from(key.publicJwk.x, "base64url");
    const header = b64url(JSON.stringify({ alg: "HS256", kid: key.kid }));
    const payload = b64url(samplePayload());
    const mac = createHmac("sha256", publicKeyBytes)
      .update(`${header}.${payload}`)
      .digest();
    const attack = `${header}.${payload}.${b64url(mac)}`;

    try {
      verifyCompact(attack, buildJwks([key.publicJwk]));
      expect.unreachable("HS256 substitution must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("alg_rejected");
    }
  });

  it("rejects a tampered payload (decision flipped deny → allow, sig untouched)", () => {
    const key = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    const [header, payloadB64, signature] = jws.split(".") as [string, string, string];
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as { decision: string };
    payload.decision = "allow";
    const tampered = `${header}.${b64url(canonicalBytes(payload))}.${signature}`;

    try {
      verifyCompact(tampered, buildJwks([key.publicJwk]));
      expect.unreachable("tampered payload must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("signature_invalid");
    }
  });

  it("rejects a tampered signature", () => {
    const key = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    const [header, payload, signature] = jws.split(".") as [string, string, string];
    // Flip one character in the MIDDLE of the signature segment (trailing
    // base64url characters can carry ignored padding bits).
    const mid = Math.floor(signature.length / 2);
    const flippedChar = signature[mid] === "A" ? "B" : "A";
    const tampered = `${header}.${payload}.${signature.slice(0, mid)}${flippedChar}${signature.slice(mid + 1)}`;
    try {
      verifyCompact(tampered, buildJwks([key.publicJwk]));
      expect.unreachable("tampered signature must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("signature_invalid");
    }
  });

  it("rejects a signature from the WRONG key presented under a known kid", () => {
    const honest = generateSigningKey();
    const attacker = generateSigningKey();
    // Attacker signs with their own key but claims the honest kid.
    const jws = signCompact(samplePayload(), {
      ...attacker,
      kid: honest.kid,
    });
    try {
      verifyCompact(jws, buildJwks([honest.publicJwk]));
      expect.unreachable("wrong-key signature must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("signature_invalid");
    }
  });

  it("rejects an unknown kid", () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    try {
      verifyCompact(jws, buildJwks([other.publicJwk]));
      expect.unreachable("unknown kid must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("kid_unknown");
    }
  });

  it('rejects tokens carrying a "crit" header parameter', () => {
    const key = generateSigningKey();
    const header = b64url(
      JSON.stringify({ alg: "EdDSA", kid: key.kid, crit: ["exp"], exp: 0 }),
    );
    const payload = b64url(samplePayload());
    const attack = `${header}.${payload}.${b64url("sig")}`;
    try {
      verifyCompact(attack, buildJwks([key.publicJwk]));
      expect.unreachable("crit must be rejected");
    } catch (error) {
      expect((error as JwsError).code).toBe("crit_rejected");
    }
  });

  it("the standalone verifier rejects the same attacks at the alg-pinning gate", () => {
    const key = generateSigningKey();
    const jwks = buildJwks([key.publicJwk]);
    const payload = b64url(samplePayload());

    const none = `${b64url(JSON.stringify({ alg: "none", kid: key.kid }))}.${payload}.${b64url("x")}`;
    const noneResult = verifyEvidence({ jws: none, jwks });
    expect(noneResult.ok).toBe(false);
    expect(noneResult.checks.at(-1)?.id).toBe("alg-pinned");

    const publicKeyBytes = Buffer.from(key.publicJwk.x, "base64url");
    const hsHeader = b64url(JSON.stringify({ alg: "HS256", kid: key.kid }));
    const mac = createHmac("sha256", publicKeyBytes)
      .update(`${hsHeader}.${payload}`)
      .digest();
    const hs256 = `${hsHeader}.${payload}.${b64url(mac)}`;
    const hsResult = verifyEvidence({ jws: hs256, jwks });
    expect(hsResult.ok).toBe(false);
    expect(hsResult.checks.at(-1)?.id).toBe("alg-pinned");
  });

  it("the standalone verifier rejects a JWKS whose kid is not the key's thumbprint", () => {
    const key = generateSigningKey();
    const swapped = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    // Key material swapped under the honest kid — thumbprint check must catch it.
    const forgedJwks = { keys: [{ ...swapped.publicJwk, kid: key.kid }] };
    const result = verifyEvidence({ jws, jwks: forgedJwks });
    expect(result.ok).toBe(false);
    expect(result.checks.at(-1)?.id).toBe("key-resolution");
  });
});

describe("did:key encoding", () => {
  it("round-trips raw Ed25519 public keys through did:key", () => {
    const key = generateSigningKey();
    const raw = new Uint8Array(Buffer.from(key.publicJwk.x, "base64url"));
    const did = didKeyFromRawPublicKey(raw);
    // Ed25519 did:key identifiers always start z6Mk (multicodec 0xed01 prefix).
    expect(did.startsWith("did:key:z6Mk")).toBe(true);
    expect(Buffer.from(rawPublicKeyFromDidKey(did)).equals(Buffer.from(raw))).toBe(true);
    expect(key.did).toBe(did);
  });

  it("rejects non-Ed25519 did:key inputs", () => {
    expect(() => rawPublicKeyFromDidKey("did:key:abc")).toThrow();
    expect(() => didKeyFromRawPublicKey(new Uint8Array(16))).toThrow();
  });

  it("base58btc handles leading zero bytes (first-principles vector)", () => {
    // alphabet[1] === "2"; each leading zero byte encodes as a leading "1".
    expect(base58btcEncode(Uint8Array.from([0, 0, 1]))).toBe("112");
    const roundTrip = base58btcDecode(base58btcEncode(Uint8Array.from([0, 7, 255, 0])));
    expect(Buffer.from(roundTrip).equals(Buffer.from([0, 7, 255, 0]))).toBe(true);
  });
});
