/**
 * JWS-compact (RFC 7515) over Ed25519, alg pinned to "EdDSA" (RFC 8037).
 *
 * Signing and verification run on node:crypto only. The `jose` library is used
 * exclusively as an independent ORACLE in tests (cross-check), never at runtime.
 *
 * Verification REJECTS, never falls through:
 *  - alg other than exactly "EdDSA" (kills alg:none and HS256-substitution),
 *  - any "crit" parameter (we implement no extensions),
 *  - unknown kid, non-OKP/Ed25519 keys, malformed structure, bad signatures.
 */
import { createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { computeKid } from "./keys.ts";
import type { PublicJwk, SigningKey } from "./keys.ts";

/** The only signature algorithm this service ever produces or accepts. */
export const EVIDENCE_JWS_ALG = "EdDSA" as const;

export type JwsErrorCode =
  | "malformed"
  | "alg_rejected"
  | "crit_rejected"
  | "kid_unknown"
  | "key_invalid"
  | "signature_invalid"
  | "payload_not_json";

export class JwsError extends Error {
  override name = "JwsError";
  readonly code: JwsErrorCode;

  constructor(code: JwsErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

const encoder = new TextEncoder();

function b64url(data: Uint8Array | string): string {
  return Buffer.from(data).toString("base64url");
}

/**
 * RFC 7515 base64url segments are canonical and UNPADDED. Node's decoder ignores
 * `=` padding and a final character's low "don't-care" bits, so many distinct
 * strings decode to the same bytes. For the signature segment — the one segment
 * the signature itself cannot cover — that is malleability: byte-different
 * artifacts that all verify. Require each segment to round-trip exactly (decode,
 * then re-encode, must reproduce it). Kept in lockstep with the offline verifier
 * (verifier/verify.mjs), so the two verification surfaces never disagree.
 */
function isCanonicalB64url(text: string): boolean {
  return Buffer.from(text, "base64url").toString("base64url") === text;
}

/** Sign payload bytes into a JWS-compact string with protected header {alg, kid}. */
export function signCompact(payload: Uint8Array, key: SigningKey): string {
  const protectedHeader = { alg: EVIDENCE_JWS_ALG, kid: key.kid };
  const signingInput = `${b64url(JSON.stringify(protectedHeader))}.${b64url(payload)}`;
  const signature = edSign(null, encoder.encode(signingInput), key.privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

export interface VerifiedJws {
  header: { alg: typeof EVIDENCE_JWS_ALG; kid: string };
  payloadBytes: Uint8Array;
  payload: unknown;
  key: PublicJwk;
}

function publicKeyObjectFromJwk(jwk: PublicJwk): KeyObject {
  try {
    return createPublicKey({
      key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
      format: "jwk",
    });
  } catch {
    throw new JwsError("key_invalid", "JWKS key could not be imported");
  }
}

/**
 * Verify a JWS-compact string against a JWKS. Throws JwsError on ANY defect;
 * a returned value means every check passed.
 */
export function verifyCompact(
  jws: string,
  jwks: { keys: readonly PublicJwk[] },
): VerifiedJws {
  if (typeof jws !== "string") throw new JwsError("malformed", "JWS must be a string");
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new JwsError("malformed", "JWS-compact must have exactly 3 parts");
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (headerB64 === "" || payloadB64 === "" || signatureB64 === "") {
    throw new JwsError("malformed", "JWS-compact has an empty segment");
  }
  // Reject non-canonical base64url (padding, a non-canonical final character) so
  // the signature segment — the only segment the signature cannot cover — cannot
  // be malleated into a byte-different artifact that still verifies.
  if (
    !isCanonicalB64url(headerB64) ||
    !isCanonicalB64url(payloadB64) ||
    !isCanonicalB64url(signatureB64)
  ) {
    throw new JwsError("malformed", "a JWS segment is not canonical unpadded base64url (RFC 7515)");
  }

  let headerValue: unknown;
  try {
    headerValue = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  } catch {
    throw new JwsError("malformed", "protected header is not valid JSON");
  }
  // JSON.parse can yield null/arrays/primitives — only an OBJECT is a header.
  // (Without this guard, `null` would crash property access with a TypeError
  // instead of the JwsError this module promises on ANY defect.)
  if (
    headerValue === null ||
    typeof headerValue !== "object" ||
    Array.isArray(headerValue)
  ) {
    throw new JwsError("malformed", "protected header is not a JSON object");
  }
  const header = headerValue as Record<string, unknown>;

  // Pin the algorithm BEFORE any key material is touched.
  if (header["alg"] !== EVIDENCE_JWS_ALG) {
    throw new JwsError(
      "alg_rejected",
      `alg must be exactly "${EVIDENCE_JWS_ALG}" (got ${JSON.stringify(header["alg"])})`,
    );
  }
  if ("crit" in header) {
    throw new JwsError("crit_rejected", "crit header parameters are not supported");
  }
  const kid = header["kid"];
  if (typeof kid !== "string" || kid === "") {
    throw new JwsError("malformed", "protected header must carry a non-empty kid");
  }

  // Tolerate a malformed (null/undefined) JWKS entry instead of throwing a raw
  // TypeError on `.kid` access: verifyCompact promises a JwsError on ANY defect and
  // accepts arbitrary caller objects (mirrors verifier/verify.mjs's guarded find).
  // A non-conforming entry is skipped; an unmatched kid then yields kid_unknown.
  const found = (jwks.keys as readonly (PublicJwk | null | undefined)[]).find(
    (key) => key != null && key.kid === kid,
  );
  if (!found) throw new JwsError("kid_unknown", `kid ${kid} not present in JWKS`);
  // Snapshot the matched key with a SINGLE read per field. verifyCompact is exported
  // and accepts arbitrary objects, so reading jwk.x once for the thumbprint check and
  // again when building the verifying key would let a hostile getter/Proxy present
  // honest.x to the check and attacker.x to the key (a property-read TOCTOU). Only
  // this snapshot — never the caller's object — is used below. The kid is bound to
  // the PROTECTED-HEADER kid (already matched at find), NOT a second read of
  // found.kid: a hostile kid getter could otherwise return the header kid at find and
  // an attacker kid here, and the thumbprint check below would then bind x to the
  // attacker kid — verifying under a key whose kid disagrees with the one the
  // artifact claims. Using the header kid forces computeKid(x) to equal that claim.
  const jwk: PublicJwk = {
    kty: found.kty,
    crv: found.crv,
    x: found.x,
    kid,
    alg: found.alg,
    use: found.use,
  };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new JwsError("key_invalid", "JWKS key is not an Ed25519 OKP key");
  }
  // kid integrity: the kid MUST equal the key's own RFC 7638 thumbprint, so a
  // JWKS can never present substituted key material under a trusted kid. This
  // brings the in-process verifier to parity with the standalone offline verifier,
  // which already enforces it (verifier/verify.mjs step 3) — the one divergence
  // both cross-vendor review passes flagged between the two verification surfaces.
  if (computeKid(jwk.x) !== jwk.kid) {
    throw new JwsError(
      "key_invalid",
      "JWKS kid is not the key's RFC 7638 thumbprint — key material may have been swapped",
    );
  }

  const keyObject = publicKeyObjectFromJwk(jwk);
  const signingInput = encoder.encode(`${headerB64}.${payloadB64}`);
  const signature = Buffer.from(signatureB64, "base64url");
  if (signature.length !== 64) {
    throw new JwsError("signature_invalid", "Ed25519 signature is not exactly 64 bytes");
  }
  if (!edVerify(null, signingInput, keyObject, signature)) {
    throw new JwsError("signature_invalid", "Ed25519 signature verification failed");
  }

  const payloadBytes = new Uint8Array(Buffer.from(payloadB64, "base64url"));
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
  } catch {
    throw new JwsError("payload_not_json", "payload is not valid JSON");
  }

  return {
    header: { alg: EVIDENCE_JWS_ALG, kid },
    payloadBytes,
    payload,
    key: jwk,
  };
}
