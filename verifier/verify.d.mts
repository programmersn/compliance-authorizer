/**
 * Type declarations for the standalone offline verifier (verify.mjs).
 * The implementation stays plain JavaScript on purpose — auditable with no
 * toolchain — but tests import it with types.
 */
export interface VerificationCheck {
  id: string;
  title: string;
  ok: boolean;
  detail: string;
}

export interface VerificationResult {
  ok: boolean;
  checks: VerificationCheck[];
  envelope: Record<string, unknown> | null;
  /**
   * kid + did:key of the verifying key. Populated ONLY after the Ed25519
   * signature verifies (null on any structural / alg / key-resolution / signature
   * failure), so it never names a key that did not actually sign these bytes.
   * Compare against the issuer's published fingerprint (obtained out-of-band).
   */
  issuer: { kid: string; did: string } | null;
}

export function jcsCanonicalize(value: unknown): string;

/**
 * True iff `text` is canonical, unpadded RFC 7515 base64url (decode then
 * re-encode reproduces the input). Reused by the offline replay CLI to reject a
 * non-canonical JWS segment as malformed input.
 */
export const isCanonicalB64url: (text: string) => boolean;

/**
 * Complete v0.1 envelope-shape validation: returns a precise failure reason, or
 * null when the envelope conforms exactly (object, exact required field set,
 * valid `decision`, and every field's type/format). Shape only. Exported so the
 * offline replay CLI gates malformed artifacts on the same single source of truth.
 */
export function validateEnvelopeShape(envelope: unknown): string | null;

export function verifyEvidence(input: {
  jws: string;
  jwks: { keys?: unknown[] };
  pack?: unknown;
}): VerificationResult;
