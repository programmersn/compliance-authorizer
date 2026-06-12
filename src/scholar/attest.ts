/**
 * Scholar-attestation PATH (ET20) — the machinery a CERTIFIED v1.0 rule pack
 * WOULD use to bind a scholar's endorsement to a specific rule pack, shipped at
 * v0.1 only as a labeled UNCERTIFIED specimen (see src/scholar/specimen.ts and
 * examples/scholar-attestation.specimen.json), never a bare null.
 *
 * This is forward-projection: at v0.1 the served evidence envelope's
 * scholar_signature_ref stays the UNCERTIFIED_SCHOLAR_REF (scholar_did:null,
 * signature:null — src/evidence/envelope.ts), and that ref's certification_note
 * already describes exactly this path:
 *
 *   "a certified v1.0 pack would carry the scholar's did:key and a detached JWS
 *    over rule_pack_hash here"
 *
 * The shape below aligns to that note: an attestation carries the scholar's
 * did:key, a DETACHED JWS, and binds it to a specific rule_pack_hash.
 *
 * Trust model — IDENTICAL to the agent credential (src/vc/verify.ts), NOT the
 * evidence envelope:
 *   - JWS-compact over Ed25519, alg pinned to exactly "EdDSA" (alg:none and any
 *     substituted algorithm are rejected BEFORE key material is touched).
 *   - The signer is a did:key DID carried as the protected header `kid`. did:key
 *     is SELF-CERTIFYING — the DID encodes the Ed25519 public key itself, so
 *     verifyScholarAttestation needs NO key distribution and works fully OFFLINE
 *     from the attestation alone. (A certified pack's scholar key is published
 *     out-of-band; the verifier proves consistency with the did:key it is given,
 *     exactly as verify.mjs proves consistency with the JWKS it is handed.)
 *
 * "DETACHED" here means: the signed payload (the claim — did + metadata +
 * rule_pack_hash) is RECONSTRUCTED by the verifier from the attestation's own
 * fields rather than read out of the JWS, and the JWS payload segment is empty.
 * Signing the whole claim together (did + metadata + rule_pack_hash) is what
 * makes the attestation tamper-evident AS A WHOLE: flip any metadata field, the
 * scholar_did, or the bound rule_pack_hash and the signature no longer verifies.
 *
 * Determinism: signing is pure Ed25519 over canonical (RFC 8785) bytes — no
 * clock, no network, no randomness, no LLM. Same key + same claim → byte-stable
 * signature, which is what lets the committed specimen be regenerated identically.
 *
 * SYNTHETIC DATA ONLY: metadata holds generic synthetic placeholders. The
 * specimen names NO real scholar or certifying body. v0.1 carries NO expiry, NO
 * revocation, NO status beyond the uncertified/specimen labeling.
 */
import { createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalBytes } from "../crypto/canonicalize.ts";
import { rawPublicKeyFromDidKey } from "../crypto/keys.ts";
import type { SigningKey } from "../crypto/keys.ts";

/**
 * Closed attestation-claim format identifier. Pinned exactly: a claim of any
 * other (or missing) type is rejected — there is no format negotiation at v0.1.
 * The /0.1 suffix versions the SHAPE a certified pack's attestation would carry.
 */
export const SCHOLAR_ATTESTATION_TYPE = "synthetic-scholar-attestation/0.1" as const;

/** The only signature algorithm a scholar attestation ever produces or accepts. */
const SCHOLAR_ATTESTATION_ALG = "EdDSA" as const;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export type ScholarAttestationErrorCode =
  | "malformed" //          attestation object / JWS structure is not the closed shape
  | "alg_rejected" //       alg is not exactly "EdDSA" (alg:none, HS256, ...)
  | "issuer_invalid" //     kid is not a resolvable ed25519 did:key, or did ≠ kid
  | "signature_invalid" //  Ed25519 signature does not verify over the claim bytes
  | "claim_invalid"; //     metadata / rule_pack_hash binding is not the exact shape

export class ScholarAttestationError extends Error {
  override name = "ScholarAttestationError";
  readonly code: ScholarAttestationErrorCode;

  constructor(code: ScholarAttestationErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Named-scholar / certifying-body METADATA SHAPE. This is the descriptive
 * envelope a certified pack's attestation WOULD carry alongside the signature.
 * Exact, closed key set (no unknown fields) — the same closed-shape discipline
 * as the agent credential's claim. SYNTHETIC placeholders only at v0.1.
 */
export interface ScholarMetadata {
  /** Scholar's name. At v0.1 a synthetic placeholder — never a real person. */
  name: string;
  /** Certifying body. At v0.1 a synthetic placeholder — never a real institution. */
  body: string;
  /** The scholar's role on the certifying body (e.g. "committee member"). */
  role: string;
  /** Attestation date, an ISO-8601 calendar date (YYYY-MM-DD). */
  date: string;
}

/**
 * A scholar attestation: the scholar's did:key, a detached JWS binding the whole
 * claim, and the human-facing metadata. Aligned to the envelope's
 * certification_note (did:key + detached JWS over rule_pack_hash).
 */
export interface ScholarAttestation {
  /** Format identifier (pinned to SCHOLAR_ATTESTATION_TYPE). */
  attestation_type: typeof SCHOLAR_ATTESTATION_TYPE;
  /** The self-certifying scholar DID (did:key) whose key signed the claim. */
  scholar_did: string;
  /** The rule pack this attestation is bound to (sha256 hex of JCS(pack)). */
  rule_pack_hash: string;
  /** Named-scholar / certifying-body metadata (synthetic at v0.1). */
  metadata: ScholarMetadata;
  /** Detached JWS-compact (empty payload segment) over the canonical claim. */
  signature: string;
}

const METADATA_KEYS = ["name", "body", "role", "date"] as const;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasExactKeys = (
  obj: Record<string, unknown>,
  keys: readonly string[],
): boolean => {
  const own = Object.keys(obj);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(obj, key));
};

/**
 * RFC 7515 segments are canonical, UNPADDED base64url. Node's decoder is lenient
 * (ignores `=` padding and a final character's don't-care bits), so a
 * byte-different signature could otherwise decode identically — reject every
 * non-canonical encoding by requiring an exact decode → re-encode round-trip.
 * (Same malleability posture as src/crypto/jws.ts, src/vc/verify.ts, verify.mjs.)
 */
const isCanonicalB64url = (text: string): boolean =>
  Buffer.from(text, "base64url").toString("base64url") === text;

function fail(code: ScholarAttestationErrorCode, message: string): never {
  throw new ScholarAttestationError(code, message);
}

/**
 * Validate a metadata object as the exact closed ScholarMetadata shape. Returns
 * a precise failure reason, or null when it conforms. Pure; no side effects.
 */
function validateMetadata(value: unknown): string | null {
  if (!isPlainObject(value)) return "metadata is not an object";
  if (!hasExactKeys(value, METADATA_KEYS)) {
    return 'metadata must carry exactly {"body","date","name","role"}';
  }
  for (const key of METADATA_KEYS) {
    const member = value[key];
    if (typeof member !== "string" || member === "") {
      return `metadata.${key} must be a non-empty string`;
    }
  }
  if (!ISO_DATE.test(value["date"] as string)) {
    return "metadata.date must be an ISO-8601 calendar date (YYYY-MM-DD)";
  }
  return null;
}

/**
 * The canonical SIGNED CLAIM bytes — the exact payload the scholar's key signs
 * and the verifier reconstructs. Binds the type, the scholar DID, the metadata,
 * and the rule_pack_hash together, so tampering with ANY of them breaks the
 * signature. RFC 8785 canonical, so one claim content has exactly one byte form.
 */
function claimBytes(
  scholarDid: string,
  rulePackHash: string,
  metadata: ScholarMetadata,
): Uint8Array {
  // Build a plain object with ONLY the four metadata members, in a fixed
  // construction (canonicalize sorts keys, so insertion order is irrelevant —
  // but projecting explicitly keeps a hostile metadata object's extra/own
  // getters out of the signed bytes).
  return canonicalBytes({
    attestation_type: SCHOLAR_ATTESTATION_TYPE,
    scholar_did: scholarDid,
    rule_pack_hash: rulePackHash,
    metadata: {
      name: metadata.name,
      body: metadata.body,
      role: metadata.role,
      date: metadata.date,
    },
  });
}

/**
 * Create a scholar attestation: a detached JWS over the (type + scholar_did +
 * rule_pack_hash + metadata) claim, signed with the scholar's Ed25519 key. The
 * header kid is the scholar's did:key (self-certifying), NOT a JWKS thumbprint —
 * the SAME trust model as the agent credential, deliberately distinct from the
 * evidence-envelope signer.
 *
 * @param rulePackHash sha256 hex of JCS(rule pack) — the pack being attested.
 * @param scholarSigningKey the scholar's Ed25519 SigningKey (synthetic at v0.1).
 * @param metadata the named-scholar / certifying-body metadata (synthetic at v0.1).
 */
export function createScholarAttestation(
  rulePackHash: string,
  scholarSigningKey: SigningKey,
  metadata: ScholarMetadata,
): ScholarAttestation {
  if (typeof rulePackHash !== "string" || !SHA256_HEX.test(rulePackHash)) {
    fail("claim_invalid", "rule_pack_hash must be a lowercase sha256 hex digest");
  }
  const metadataError = validateMetadata(metadata);
  if (metadataError !== null) fail("claim_invalid", metadataError);

  const scholarDid = scholarSigningKey.did;
  // Protected header carries EXACTLY {alg, kid}; the closed header mirrors the
  // agent credential — no crit, no typ, no smuggled parameters.
  const headerB64 = Buffer.from(
    JSON.stringify({ alg: SCHOLAR_ATTESTATION_ALG, kid: scholarDid }),
    "utf8",
  ).toString("base64url");
  // DETACHED JWS: the signing input is `header..` (empty payload segment). The
  // payload that is actually signed is the reconstructable claim bytes, NOT
  // carried in the JWS — the verifier rebuilds them from the attestation fields.
  const signingInput = `${headerB64}.${Buffer.from(
    claimBytes(scholarDid, rulePackHash, metadata),
  ).toString("base64url")}`;
  const signature = edSign(
    null,
    Buffer.from(signingInput, "utf8"),
    scholarSigningKey.privateKey,
  );
  // The attestation's `signature` is the DETACHED compact form: header, an EMPTY
  // payload segment, and the signature. (The claim travels in the sibling fields,
  // bound by being part of the signed bytes above.)
  const detachedJws = `${headerB64}..${Buffer.from(signature).toString("base64url")}`;

  return {
    attestation_type: SCHOLAR_ATTESTATION_TYPE,
    scholar_did: scholarDid,
    rule_pack_hash: rulePackHash,
    metadata: {
      name: metadata.name,
      body: metadata.body,
      role: metadata.role,
      date: metadata.date,
    },
    signature: detachedJws,
  };
}

/** The verified, presentation-ready content of a scholar attestation. */
export interface VerifiedScholarAttestation {
  scholar_did: string;
  rule_pack_hash: string;
  metadata: ScholarMetadata;
}

/**
 * Verify a scholar attestation OFFLINE from the did:key alone, bound to an
 * EXPECTED rule_pack_hash. Throws ScholarAttestationError on ANY defect; a
 * returned value means every check passed: the attestation is the closed shape,
 * the metadata is exact, the embedded rule_pack_hash equals the expected one,
 * the signing did:key resolves, and the Ed25519 signature verifies over the
 * reconstructed claim — so the whole claim is intact and was signed by that DID.
 *
 * Check order mirrors the agent-credential verifier: structure → alg pin (before
 * key material) → issuer key → signature → claim binding.
 *
 * @param attestation the attestation object to verify (arbitrary untrusted input).
 * @param rulePackHash the rule_pack_hash the caller expects this to be bound to.
 */
export function verifyScholarAttestation(
  attestation: unknown,
  rulePackHash: string,
): VerifiedScholarAttestation {
  if (typeof rulePackHash !== "string" || !SHA256_HEX.test(rulePackHash)) {
    fail("claim_invalid", "expected rule_pack_hash must be a lowercase sha256 hex digest");
  }

  // 0. Attestation object shape: EXACTLY the five fields. Snapshot each field
  // with a single read — verifyScholarAttestation accepts arbitrary objects, so
  // a hostile getter must not be able to present one value to a check and another
  // to the signed-claim reconstruction (a property-read TOCTOU, the same posture
  // as src/crypto/jws.ts and verify.mjs). Only these locals are used below.
  if (!isPlainObject(attestation)) {
    fail("malformed", "scholar attestation must be a JSON object");
  }
  if (
    !hasExactKeys(attestation, [
      "attestation_type",
      "scholar_did",
      "rule_pack_hash",
      "metadata",
      "signature",
    ])
  ) {
    fail(
      "malformed",
      'scholar attestation must carry exactly {"attestation_type","metadata","rule_pack_hash","scholar_did","signature"}',
    );
  }
  const attestationType = attestation["attestation_type"];
  const scholarDid = attestation["scholar_did"];
  const boundPackHash = attestation["rule_pack_hash"];
  const metadataValue = attestation["metadata"];
  const signature = attestation["signature"];

  if (attestationType !== SCHOLAR_ATTESTATION_TYPE) {
    fail(
      "claim_invalid",
      `scholar attestation attestation_type must be exactly "${SCHOLAR_ATTESTATION_TYPE}" ` +
        `(got ${JSON.stringify(attestationType)})`,
    );
  }
  if (typeof scholarDid !== "string" || scholarDid === "") {
    fail("issuer_invalid", "scholar attestation scholar_did must be a non-empty did:key string");
  }
  if (typeof boundPackHash !== "string" || !SHA256_HEX.test(boundPackHash)) {
    fail("claim_invalid", "scholar attestation rule_pack_hash is not a lowercase sha256 hex digest");
  }
  const metadataError = validateMetadata(metadataValue);
  if (metadataError !== null) fail("claim_invalid", metadataError);
  const metadata = metadataValue as ScholarMetadata;

  // 1. Binding: the attestation must be bound to the rule pack the caller asked
  // about. A mismatch is a CLAIM defect (the signature may be perfectly valid
  // over a DIFFERENT pack) — surface it precisely, not as a signature failure.
  if (boundPackHash !== rulePackHash) {
    fail(
      "claim_invalid",
      "scholar attestation rule_pack_hash does not match the expected rule pack — " +
        "this attestation is bound to a different pack",
    );
  }

  // 2. Detached-JWS structure: exactly `header..signature` (an EMPTY middle
  // payload segment is what makes it DETACHED), header and signature canonical
  // base64url. A present payload segment is rejected — the claim must come from
  // the attestation fields, never from inside the JWS.
  if (typeof signature !== "string") {
    fail("malformed", "scholar attestation signature must be a detached JWS-compact string");
  }
  const parts = signature.split(".");
  if (parts.length !== 3) {
    fail("malformed", "scholar attestation signature is not a 3-segment JWS-compact string");
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (payloadB64 !== "") {
    fail(
      "malformed",
      "scholar attestation signature must be DETACHED (empty payload segment) — " +
        "the claim is reconstructed from the attestation fields",
    );
  }
  if (headerB64 === "" || signatureB64 === "") {
    fail("malformed", "scholar attestation signature has an empty header or signature segment");
  }
  if (!isCanonicalB64url(headerB64) || !isCanonicalB64url(signatureB64)) {
    fail(
      "malformed",
      "a scholar-attestation signature segment is not canonical unpadded base64url (RFC 7515)",
    );
  }

  // 3. Protected header: a JSON object carrying EXACTLY {alg, kid}; alg pinned
  // BEFORE any key material is touched. The kid must equal the scholar_did field
  // — the signed claim names the DID, and the header resolves the SAME key.
  let headerValue: unknown;
  try {
    headerValue = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  } catch {
    fail("malformed", "scholar-attestation protected header is not valid JSON");
  }
  if (!isPlainObject(headerValue)) {
    fail("malformed", "scholar-attestation protected header is not a JSON object");
  }
  if (headerValue["alg"] !== SCHOLAR_ATTESTATION_ALG) {
    fail(
      "alg_rejected",
      `scholar-attestation alg must be exactly "${SCHOLAR_ATTESTATION_ALG}" ` +
        `(got ${JSON.stringify(headerValue["alg"])}); alg:none and substituted algorithms are rejected`,
    );
  }
  if (!hasExactKeys(headerValue, ["alg", "kid"])) {
    fail(
      "malformed",
      'scholar-attestation protected header must carry exactly {"alg","kid"} — no other parameters',
    );
  }
  const headerKid = headerValue["kid"];
  if (typeof headerKid !== "string" || headerKid === "") {
    fail("issuer_invalid", "scholar-attestation header kid must be a non-empty did:key string");
  }
  // Issuer binding: the header kid must equal the scholar_did the signature
  // covers (a hostile attestation cannot resolve key A in the header while
  // claiming did B in the signed/displayed fields).
  if (headerKid !== scholarDid) {
    fail(
      "issuer_invalid",
      "scholar-attestation header kid does not match the scholar_did the claim binds",
    );
  }

  // 4. Issuer key: the kid IS the key (did:key, self-certifying). Decode the
  // ed25519-pub multicodec DID to the raw 32-byte key and import it. No JWKS, no
  // network, no key distribution — verification is possible fully offline.
  let publicKey;
  try {
    const raw = rawPublicKeyFromDidKey(headerKid);
    publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") },
      format: "jwk",
    });
  } catch (error) {
    fail(
      "issuer_invalid",
      "scholar-attestation kid is not a resolvable ed25519 did:key " +
        `(${error instanceof Error ? error.message : String(error)})`,
    );
  }

  // 5. Signature: exactly 64 bytes, verifying over `header.<RECONSTRUCTED
  // claim>`. The signing input rebuilds the payload from the attestation's OWN
  // fields (the detached discipline), so a flip in scholar_did, rule_pack_hash,
  // or any metadata field changes the reconstructed bytes and breaks the check.
  const signatureBytes = Buffer.from(signatureB64, "base64url");
  if (signatureBytes.length !== 64) {
    fail(
      "signature_invalid",
      "scholar-attestation signature does not decode to exactly 64 bytes (Ed25519)",
    );
  }
  const reconstructedPayloadB64 = Buffer.from(
    claimBytes(scholarDid, boundPackHash, metadata),
  ).toString("base64url");
  const signingInput = Buffer.from(`${headerB64}.${reconstructedPayloadB64}`, "utf8");
  if (!edVerify(null, signingInput, publicKey, signatureBytes)) {
    fail(
      "signature_invalid",
      "scholar-attestation Ed25519 signature does not verify over the reconstructed claim — " +
        "the attestation was tampered with or was not signed by this did:key",
    );
  }

  return {
    scholar_did: scholarDid,
    rule_pack_hash: boundPackHash,
    metadata: {
      name: metadata.name,
      body: metadata.body,
      role: metadata.role,
      date: metadata.date,
    },
  };
}
