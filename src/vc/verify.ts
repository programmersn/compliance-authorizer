/**
 * Synthetic agent-credential verification (ET16, D6/CXT-C — the MINIMAL signed
 * VC, deliberately NOT a W3C Verifiable Credential):
 *
 *   - JWS-compact over Ed25519, alg pinned to exactly "EdDSA" (alg:none and any
 *     substituted algorithm are rejected BEFORE key material is touched).
 *   - The issuer is a did:key DID carried as the protected header `kid`. did:key
 *     is SELF-CERTIFYING: the DID encodes the Ed25519 public key itself, so
 *     verification needs NO key distribution and works fully OFFLINE — which is
 *     what lets decision replay re-verify the credential with zero extra inputs.
 *   - The payload encodes ONE thing: an allowed-MCC scope for a synthetic agent.
 *     NO revocation, NO status, NO expiry checking (explicitly locked out of
 *     v0.1 scope).
 *
 * error ≠ deny: an INVALID credential is never a decision input. The caller maps
 * AgentCredentialError to a 4xx problem+json at the API boundary (no envelope is
 * signed), and to a conclusive NOT-REPRODUCED verdict at replay (an honest
 * engine refuses such an intent and never signs a decision for it).
 *
 * Determinism: verification is a pure function of the credential bytes — no
 * clock (nothing expires at v0.1), no network, no randomness, no LLM.
 */
import { createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalize } from "../crypto/canonicalize.ts";
import { rawPublicKeyFromDidKey } from "../crypto/keys.ts";

/**
 * Closed credential format identifier. Pinned exactly: a credential of any
 * other (or missing) type is rejected — there is no format negotiation at v0.1.
 */
export const AGENT_CREDENTIAL_TYPE = "synthetic-agent-mcc-scope/0.1";

export type AgentCredentialErrorCode =
  | "malformed" //          not a 3-segment canonical-base64url JWS / bad header shape
  | "alg_rejected" //       alg is not exactly "EdDSA" (alg:none, HS256, ...)
  | "issuer_invalid" //     kid is not a resolvable ed25519 did:key, or issuer ≠ kid
  | "signature_invalid" //  Ed25519 signature does not verify over these bytes
  | "payload_invalid"; //   payload is not the canonical, schema-exact scope claim

export class AgentCredentialError extends Error {
  override name = "AgentCredentialError";
  readonly code: AgentCredentialErrorCode;

  constructor(code: AgentCredentialErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/** The verified, decision-ready content of a presented credential. */
export interface VerifiedAgentCredential {
  /** The self-certifying issuer DID (did:key) whose key signed the credential. */
  issuer_did: string;
  /** Synthetic agent label (generic synthetic identifiers only — never real names). */
  agent_id: string;
  /** The allowed-MCC scope: the ONLY permission the credential encodes at v0.1. */
  allowed_mcc: readonly string[];
}

const MCC_PATTERN = /^[0-9]{4}$/;

/**
 * RFC 7515 segments are canonical, UNPADDED base64url. Node's decoder is
 * lenient (ignores `=` padding and a final character's don't-care bits), so a
 * byte-different credential could otherwise decode identically — reject every
 * non-canonical encoding by requiring an exact decode → re-encode round-trip.
 * (Same malleability posture as src/crypto/jws.ts and verifier/verify.mjs.)
 */
const isCanonicalB64url = (text: string): boolean =>
  Buffer.from(text, "base64url").toString("base64url") === text;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasExactKeys = (obj: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(obj);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(obj, key));
};

function fail(code: AgentCredentialErrorCode, message: string): never {
  throw new AgentCredentialError(code, message);
}

/**
 * Verify a presented synthetic agent credential. Throws AgentCredentialError on
 * ANY defect; a returned value means every check passed. Check order mirrors the
 * evidence verifiers: structure → alg pin (before key material) → issuer key →
 * signature → payload canonical form → strict payload schema.
 */
export function verifyAgentCredential(credential: unknown): VerifiedAgentCredential {
  // 1. Structure: exactly 3 non-empty, canonical-base64url segments.
  if (typeof credential !== "string") {
    fail("malformed", "agent credential must be a JWS-compact string");
  }
  const parts = credential.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    fail("malformed", "agent credential is not a 3-segment JWS-compact string");
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (!parts.every(isCanonicalB64url)) {
    fail(
      "malformed",
      "an agent-credential segment is not canonical unpadded base64url (RFC 7515)",
    );
  }

  // 2. Protected header: a JSON object carrying EXACTLY {alg, kid}. The format
  // is closed (no crit, no typ, no extra parameters — header smuggling is
  // rejected wholesale), and alg is pinned BEFORE any key material is touched.
  let headerValue: unknown;
  try {
    headerValue = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  } catch {
    fail("malformed", "agent-credential protected header is not valid JSON");
  }
  if (!isPlainObject(headerValue)) {
    fail("malformed", "agent-credential protected header is not a JSON object");
  }
  if (headerValue["alg"] !== "EdDSA") {
    fail(
      "alg_rejected",
      `agent-credential alg must be exactly "EdDSA" (got ${JSON.stringify(headerValue["alg"])}); ` +
        "alg:none and substituted algorithms are rejected",
    );
  }
  if (!hasExactKeys(headerValue, ["alg", "kid"])) {
    fail(
      "malformed",
      'agent-credential protected header must carry exactly {"alg","kid"} — no other parameters are supported',
    );
  }
  const kid = headerValue["kid"];
  if (typeof kid !== "string" || kid === "") {
    fail("issuer_invalid", "agent-credential kid must be a non-empty did:key string");
  }

  // 3. Issuer key: the kid IS the key (did:key, self-certifying). Decode the
  // ed25519-pub multicodec DID to the raw 32-byte key and import it. No JWKS,
  // no network, no key distribution — verification is possible fully offline.
  let publicKey;
  try {
    const raw = rawPublicKeyFromDidKey(kid);
    publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") },
      format: "jwk",
    });
  } catch (error) {
    fail(
      "issuer_invalid",
      "agent-credential kid is not a resolvable ed25519 did:key " +
        `(${error instanceof Error ? error.message : String(error)})`,
    );
  }

  // 4. Signature: exactly 64 bytes, verifying over `header.payload`.
  const signatureBytes = Buffer.from(signatureB64, "base64url");
  if (signatureBytes.length !== 64) {
    fail(
      "signature_invalid",
      "agent-credential signature does not decode to exactly 64 bytes (Ed25519)",
    );
  }
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
  if (!edVerify(null, signingInput, publicKey, signatureBytes)) {
    fail(
      "signature_invalid",
      "agent-credential Ed25519 signature does not verify — the credential was tampered with or was not issued by this did:key",
    );
  }

  // 5. Payload canonical form: the payload bytes must BE their own RFC 8785
  // canonical serialization (same discipline as the evidence envelope), so one
  // credential content has exactly one byte representation.
  const payloadBytes = Buffer.from(payloadB64, "base64url");
  let payload: unknown;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    fail("payload_invalid", "agent-credential payload is not valid JSON");
  }
  if (!isPlainObject(payload)) {
    fail("payload_invalid", "agent-credential payload is not a JSON object");
  }
  let canonicalPayload: string;
  try {
    canonicalPayload = canonicalize(payload);
  } catch (error) {
    fail(
      "payload_invalid",
      "agent-credential payload cannot be canonicalized per RFC 8785 " +
        `(${error instanceof Error ? error.message : String(error)})`,
    );
  }
  if (Buffer.from(canonicalPayload, "utf8").compare(payloadBytes) !== 0) {
    fail(
      "payload_invalid",
      "agent-credential payload bytes are not the RFC 8785 canonical form of their own content",
    );
  }

  // 6. Strict payload schema — the closed v0.1 claim shape, exact key sets at
  // both levels (no unknown fields, nothing optional):
  //   { credential_type, issuer, agent_id, scope: { allowed_mcc: ["dddd", ...] } }
  if (!hasExactKeys(payload, ["credential_type", "issuer", "agent_id", "scope"])) {
    fail(
      "payload_invalid",
      'agent-credential payload must carry exactly {"credential_type","issuer","agent_id","scope"}',
    );
  }
  if (payload["credential_type"] !== AGENT_CREDENTIAL_TYPE) {
    fail(
      "payload_invalid",
      `agent-credential credential_type must be exactly "${AGENT_CREDENTIAL_TYPE}" ` +
        `(got ${JSON.stringify(payload["credential_type"])})`,
    );
  }
  // Issuer binding: the signed claim names the same did:key the header resolves.
  if (payload["issuer"] !== kid) {
    fail(
      "issuer_invalid",
      "agent-credential issuer claim does not match the did:key that signed it",
    );
  }
  const agentId = payload["agent_id"];
  if (typeof agentId !== "string" || agentId === "") {
    fail("payload_invalid", "agent-credential agent_id must be a non-empty string");
  }
  const scope = payload["scope"];
  if (!isPlainObject(scope) || !hasExactKeys(scope, ["allowed_mcc"])) {
    fail(
      "payload_invalid",
      'agent-credential scope must be an object carrying exactly {"allowed_mcc"}',
    );
  }
  const allowedMcc = scope["allowed_mcc"];
  if (!Array.isArray(allowedMcc) || allowedMcc.length === 0) {
    fail(
      "payload_invalid",
      "agent-credential scope.allowed_mcc must be a non-empty array of 4-digit MCC strings",
    );
  }
  for (let i = 0; i < allowedMcc.length; i++) {
    const mcc: unknown = allowedMcc[i];
    if (typeof mcc !== "string" || !MCC_PATTERN.test(mcc)) {
      fail(
        "payload_invalid",
        `agent-credential scope.allowed_mcc[${i}] is not a 4-digit MCC string`,
      );
    }
  }

  return {
    issuer_did: kid,
    agent_id: agentId,
    allowed_mcc: (allowedMcc as string[]).slice(),
  };
}
