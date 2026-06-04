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
  /** kid + did:key of the key that verified — compare against the issuer's published fingerprint. */
  issuer: { kid: string; did: string } | null;
}

export function jcsCanonicalize(value: unknown): string;

export function verifyEvidence(input: {
  jws: string;
  jwks: { keys?: unknown[] };
  pack?: unknown;
}): VerificationResult;
