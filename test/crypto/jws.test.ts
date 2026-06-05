/**
 * JWS sign/verify (ET11): round-trip, jose-as-oracle cross-checks, and the
 * negative-alg matrix. Every negative test EXECUTES the real attack (a
 * correctly-built malicious token), not a malformed string.
 */
import { createHmac, createPublicKey, sign as edSign } from "node:crypto";
import { CompactSign, compactVerify, calculateJwkThumbprint, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import { canonicalBytes } from "../../src/crypto/canonicalize.ts";
import {
  EVIDENCE_JWS_ALG,
  JwsError,
  type JwsErrorCode,
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

/** Assert that `fn` throws a JwsError carrying exactly `code` (never falls through). */
function expectJwsError(fn: () => unknown, code: JwsErrorCode): void {
  try {
    fn();
    expect.unreachable(`expected JwsError ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(JwsError);
    expect((error as JwsError).code).toBe(code);
  }
}

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
    expectJwsError(
      () =>
        verifyCompact(`${header}.${payload}.${b64url("sig")}`, buildJwks([key.publicJwk])),
      "alg_rejected",
    );
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

    expectJwsError(
      () => verifyCompact(attack, buildJwks([key.publicJwk])),
      "alg_rejected",
    );
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

    expectJwsError(
      () => verifyCompact(tampered, buildJwks([key.publicJwk])),
      "signature_invalid",
    );
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
    expectJwsError(
      () => verifyCompact(tampered, buildJwks([key.publicJwk])),
      "signature_invalid",
    );
  });

  it("rejects a signature from the WRONG key presented under a known kid", () => {
    const honest = generateSigningKey();
    const attacker = generateSigningKey();
    // Attacker signs with their own key but claims the honest kid.
    const jws = signCompact(samplePayload(), {
      ...attacker,
      kid: honest.kid,
    });
    expectJwsError(
      () => verifyCompact(jws, buildJwks([honest.publicJwk])),
      "signature_invalid",
    );
  });

  it("rejects an unknown kid", () => {
    const key = generateSigningKey();
    const other = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    expectJwsError(
      () => verifyCompact(jws, buildJwks([other.publicJwk])),
      "kid_unknown",
    );
  });

  it("rejects a non-Ed25519 key under a matching kid (EC P-256) with key_invalid", () => {
    // The kid resolves, but the resolved key is the wrong type. The kty/crv
    // gate fires BEFORE any key import — an EdDSA verifier must never touch a
    // non-OKP key, even if an attacker parks one under a known kid.
    const key = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    const ecJwk = {
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      kid: key.kid,
      alg: "EdDSA",
      use: "sig",
    };
    const forgedJwks = { keys: [ecJwk] } as unknown as {
      keys: (typeof key.publicJwk)[];
    };
    expectJwsError(() => verifyCompact(jws, forgedJwks), "key_invalid");
  });

  it("rejects a validly-signed JWS whose payload is not JSON (payload_not_json)", () => {
    // Sign raw non-JSON bytes with a real key: the signature verifies, the
    // alg/kid/key checks all pass, and ONLY the payload JSON.parse fails.
    const key = generateSigningKey();
    const jws = signCompact(new TextEncoder().encode("not json"), key);
    expectJwsError(
      () => verifyCompact(jws, buildJwks([key.publicJwk])),
      "payload_not_json",
    );
  });

  it("rejects a JWS whose protected header is valid JSON but not an object (null/array)", () => {
    const key = generateSigningKey();
    const payload = b64url(samplePayload());
    // JSON.parse("null") → null; a naive header.alg access would crash with a
    // TypeError instead of the JwsError this module promises on ANY defect.
    for (const headerJson of ["null", "[]"]) {
      const attack = `${b64url(headerJson)}.${payload}.${b64url("sig")}`;
      expectJwsError(() => verifyCompact(attack, buildJwks([key.publicJwk])), "malformed");
      // Verifier parity: a structured FAIL verdict, never a crash.
      const result = verifyEvidence({ jws: attack, jwks: buildJwks([key.publicJwk]) });
      expect(result.ok).toBe(false);
      expect(result.checks.at(-1)?.id).toBe("structure");
    }
  });

  it('rejects tokens carrying a "crit" header parameter', () => {
    const key = generateSigningKey();
    const header = b64url(
      JSON.stringify({ alg: "EdDSA", kid: key.kid, crit: ["exp"], exp: 0 }),
    );
    const payload = b64url(samplePayload());
    const attack = `${header}.${payload}.${b64url("sig")}`;
    expectJwsError(
      () => verifyCompact(attack, buildJwks([key.publicJwk])),
      "crit_rejected",
    );
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

  it("the standalone verifier FAILS a validly-SIGNED but non-canonical payload at the canonical-form check", () => {
    const key = generateSigningKey();
    // Keys deliberately OUT of JCS order — the signature is genuine, so only
    // the canonical-form (anti-malleability) check can catch this.
    const payloadB64 = b64url('{"z":1,"a":2}');
    const headerB64 = b64url(JSON.stringify({ alg: "EdDSA", kid: key.kid }));
    const signature = b64url(
      edSign(null, Buffer.from(`${headerB64}.${payloadB64}`, "utf8"), key.privateKey),
    );
    const result = verifyEvidence({
      jws: `${headerB64}.${payloadB64}.${signature}`,
      jwks: buildJwks([key.publicJwk]),
    });
    expect(result.ok).toBe(false);
    // The signature check itself passed — canonicality is what failed.
    expect(result.checks.find((check) => check.id === "signature")?.ok).toBe(true);
    expect(result.checks.find((check) => check.id === "canonical-form")?.ok).toBe(false);
  });

  it("the standalone verifier FAILS a deeply-nested self-signed payload with a structured verdict, never a crash", () => {
    const key = generateSigningKey();
    // 300 levels of array nesting IS canonical JSON — without the depth bound
    // the canonical-form check would overflow the stack instead of failing.
    const deepJson = "[".repeat(300) + "1" + "]".repeat(300);
    const payloadB64 = b64url(deepJson);
    const headerB64 = b64url(JSON.stringify({ alg: "EdDSA", kid: key.kid }));
    const signature = b64url(
      edSign(null, Buffer.from(`${headerB64}.${payloadB64}`, "utf8"), key.privateKey),
    );
    const result = verifyEvidence({
      jws: `${headerB64}.${payloadB64}.${signature}`,
      jwks: buildJwks([key.publicJwk]),
    });
    expect(result.ok).toBe(false);
    const canonicalCheck = result.checks.find((check) => check.id === "canonical-form");
    expect(canonicalCheck?.ok).toBe(false);
    expect(canonicalCheck?.detail).toContain("depth bound");
  });

  it("the standalone verifier rejects a validly-SIGNED null payload at the envelope-shape check", () => {
    const key = generateSigningKey();
    // "null" IS its own canonical form, so this sails through the canonical-form
    // check and must be stopped — structurally, not by a crash — at envelope-shape.
    const payloadB64 = b64url("null");
    const headerB64 = b64url(JSON.stringify({ alg: "EdDSA", kid: key.kid }));
    const signature = b64url(
      edSign(null, Buffer.from(`${headerB64}.${payloadB64}`, "utf8"), key.privateKey),
    );
    const result = verifyEvidence({
      jws: `${headerB64}.${payloadB64}.${signature}`,
      jwks: buildJwks([key.publicJwk]),
    });
    expect(result.ok).toBe(false);
    expect(result.checks.at(-1)?.id).toBe("envelope-shape");
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
  it("the standalone verifier reports the SAME issuer did:key fingerprint (independent encoder)", () => {
    const key = generateSigningKey();
    const jws = signCompact(samplePayload(), key);
    const result = verifyEvidence({ jws, jwks: buildJwks([key.publicJwk]) });
    // verifyEvidence fails later checks (payload is not a full envelope), but
    // key resolution succeeded — the issuer fingerprint must already be set.
    expect(result.issuer).toEqual({ kid: key.kid, did: key.did });
  });

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

  it("rejects a did:key carrying the wrong multicodec prefix", () => {
    // Valid base58btc body and the did:key:z multibase prefix, but the
    // multicodec bytes are NOT ed25519-pub (0xed01) → decode must refuse.
    // Non-zero filler avoids the base58 leading-zero special case.
    const filler = Array.from({ length: 32 }, () => 0x01);
    const wrongCodec = Uint8Array.from([0xaa, 0xbb, ...filler]);
    const did = `did:key:z${base58btcEncode(wrongCodec)}`;
    expect(() => rawPublicKeyFromDidKey(did)).toThrow(/multicodec/);
  });

  it("rejects a did:key with the ed25519-pub prefix but the wrong key length", () => {
    // Correct 0xed01 multicodec prefix, but only 31 key bytes follow (32 are
    // required) → the length guard must reject it.
    const filler = Array.from({ length: 31 }, () => 0x01);
    const shortKey = Uint8Array.from([0xed, 0x01, ...filler]);
    const did = `did:key:z${base58btcEncode(shortKey)}`;
    expect(() => rawPublicKeyFromDidKey(did)).toThrow(/32 key bytes/);
  });

  it("exportPrivateJwk throws when the key object carries no private 'd' scalar", () => {
    // A public-only KeyObject has no 'd'. Wrapping it as a SigningKey and asking
    // for its private JWK must throw rather than emit a 'd'-less private JWK.
    const key = generateSigningKey();
    const publicOnly = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: key.publicJwk.x },
      format: "jwk",
    });
    const fakeSigningKey = {
      privateKey: publicOnly,
      publicJwk: key.publicJwk,
      kid: key.kid,
      did: key.did,
    };
    expect(() => exportPrivateJwk(fakeSigningKey)).toThrow(/missing 'd'/);
  });

  it("base58btc handles leading zero bytes (first-principles vector)", () => {
    // alphabet[1] === "2"; each leading zero byte encodes as a leading "1".
    expect(base58btcEncode(Uint8Array.from([0, 0, 1]))).toBe("112");
    const roundTrip = base58btcDecode(base58btcEncode(Uint8Array.from([0, 7, 255, 0])));
    expect(Buffer.from(roundTrip).equals(Buffer.from([0, 7, 255, 0]))).toBe(true);
  });
});
