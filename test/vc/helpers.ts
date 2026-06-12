/**
 * Adversarial credential-minting helpers (ET17). The PRODUCTION minting path is
 * src/vc/mint.ts (signAgentCredential — the honest issuer); these helpers exist
 * to mint the DEFECTIVE variants the verifier must reject: arbitrary headers,
 * arbitrary (even non-canonical) payload bytes, real Ed25519 signatures over
 * dishonest content. SYNTHETIC DATA ONLY — generic agent/issuer labels.
 */
import { sign as edSign } from "node:crypto";
import { canonicalBytes } from "../../src/crypto/canonicalize.ts";
import type { SigningKey } from "../../src/crypto/keys.ts";
import { AGENT_CREDENTIAL_TYPE } from "../../src/vc/verify.ts";

export const b64url = (data: Uint8Array | string): string =>
  Buffer.from(data).toString("base64url");

/** The well-formed v0.1 claim object for a key, with arbitrary overrides. */
export function claimPayload(
  issuerKey: SigningKey,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    credential_type: AGENT_CREDENTIAL_TYPE,
    issuer: issuerKey.did,
    agent_id: "synthetic-travel-agent",
    scope: { allowed_mcc: ["7011"] },
    ...overrides,
  };
}

/**
 * Genuinely SIGN an arbitrary header + raw payload bytes with the issuer's
 * Ed25519 key — so a structural/schema defect is the ONLY defect (the signature
 * itself verifies), and the test pins WHICH check rejects the credential.
 */
export function signRawCredential(
  header: unknown,
  payloadBytes: Uint8Array,
  issuerKey: SigningKey,
): string {
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(payloadBytes);
  const signature = edSign(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    issuerKey.privateKey,
  );
  return `${headerB64}.${payloadB64}.${b64url(new Uint8Array(signature))}`;
}

/** Sign a (possibly defective) claim object as its canonical bytes. */
export function signClaim(
  claim: Record<string, unknown>,
  issuerKey: SigningKey,
  header: unknown = { alg: "EdDSA", kid: issuerKey.did },
): string {
  return signRawCredential(header, canonicalBytes(claim), issuerKey);
}
