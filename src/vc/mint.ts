/**
 * Synthetic agent-credential MINTING (the did:key issuer side of ET16).
 *
 * Mints the exact closed format verifyAgentCredential accepts: JWS-compact over
 * Ed25519, protected header exactly {alg:"EdDSA", kid:<issuer did:key>}, payload
 * the RFC 8785 canonical bytes of the v0.1 scope claim. The issuer is
 * self-certifying (did:key encodes the verifying key), so a minted credential
 * verifies fully offline with no key distribution.
 *
 * SYNTHETIC DATA ONLY: agent_id and issuer labels are generic synthetic
 * placeholders — never real institutions, individuals, or PII. v0.1 credentials
 * carry NO expiry, NO revocation, NO status (locked out of scope).
 *
 * This deliberately does NOT reuse signCompact (src/crypto/jws.ts): the
 * evidence-envelope JWS binds kid to the RFC 7638 JWK thumbprint resolved
 * against a JWKS, while the credential binds kid to a did:key resolved from the
 * kid itself — two different trust models that must not blur into one signer.
 */
import { sign as edSign } from "node:crypto";
import { canonicalBytes } from "../crypto/canonicalize.ts";
import type { SigningKey } from "../crypto/keys.ts";
import { AGENT_CREDENTIAL_TYPE } from "./verify.ts";

export interface AgentCredentialClaims {
  /** Generic synthetic agent label (e.g. "synthetic-travel-agent"). */
  agent_id: string;
  /** The allowed-MCC scope: 4-digit MCC strings the agent may transact in. */
  allowed_mcc: readonly string[];
}

/**
 * Sign a synthetic agent credential with the issuer's Ed25519 key. The header
 * kid is the issuer's did:key (NOT the JWKS thumbprint kid) — the credential's
 * trust anchor is the self-certifying DID, by design.
 */
export function signAgentCredential(
  claims: AgentCredentialClaims,
  issuerKey: SigningKey,
): string {
  const payload = {
    credential_type: AGENT_CREDENTIAL_TYPE,
    issuer: issuerKey.did,
    agent_id: claims.agent_id,
    scope: { allowed_mcc: [...claims.allowed_mcc] },
  };
  const headerB64 = Buffer.from(
    JSON.stringify({ alg: "EdDSA", kid: issuerKey.did }),
    "utf8",
  ).toString("base64url");
  // Canonical payload bytes — the one byte representation the verifier accepts.
  const payloadB64 = Buffer.from(canonicalBytes(payload)).toString("base64url");
  const signature = edSign(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    issuerKey.privateKey,
  );
  return `${headerB64}.${payloadB64}.${Buffer.from(signature).toString("base64url")}`;
}
