/**
 * Agent-credential format verification (ET16/ET17, the admission gate's own
 * unit surface): the closed synthetic-agent-mcc-scope/0.1 format round-trips
 * through mint → verify, and EVERY defective variant — tampered signature,
 * alg:none, HS256 substitution, malformed structure, bad did:key, missing or
 * malformed scope, non-canonical payload — is rejected with the right error
 * code. SYNTHETIC DATA ONLY (generic agent labels, throwaway generated keys).
 */
import { describe, expect, it } from "vitest";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import { signAgentCredential } from "../../src/vc/mint.ts";
import {
  AGENT_CREDENTIAL_TYPE,
  AgentCredentialError,
  verifyAgentCredential,
} from "../../src/vc/verify.ts";
import { b64url, claimPayload, signClaim, signRawCredential } from "./helpers.ts";

const issuerKey = generateSigningKey();
const otherKey = generateSigningKey();

const genuine = signAgentCredential(
  { agent_id: "synthetic-travel-agent", allowed_mcc: ["7011", "5411"] },
  issuerKey,
);

/** Assert rejection with a specific AgentCredentialError code + message bit. */
function expectRejection(
  credential: unknown,
  code: string,
  messageSubstring: string,
) {
  let caught: unknown;
  try {
    verifyAgentCredential(credential);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(AgentCredentialError);
  expect((caught as AgentCredentialError).code).toBe(code);
  expect((caught as AgentCredentialError).message).toContain(messageSubstring);
}

describe("mint → verify round-trip (the honest issuer path)", () => {
  it("a minted credential verifies and yields the issuer did, agent id, and scope", () => {
    const verified = verifyAgentCredential(genuine);
    expect(verified.issuer_did).toBe(issuerKey.did);
    expect(verified.issuer_did.startsWith("did:key:z")).toBe(true); // self-certifying DID
    expect(verified.agent_id).toBe("synthetic-travel-agent");
    expect(verified.allowed_mcc).toEqual(["7011", "5411"]);
  });

  it("minting is DETERMINISTIC: same key + same claims → byte-identical credential", () => {
    // Ed25519 signing is deterministic and the payload is canonical (RFC 8785),
    // so a credential has exactly one byte representation per (key, claims).
    const again = signAgentCredential(
      { agent_id: "synthetic-travel-agent", allowed_mcc: ["7011", "5411"] },
      issuerKey,
    );
    expect(again).toBe(genuine);
  });

  it("verification is OFFLINE-complete: the did:key in the header is the only key material", () => {
    // No JWKS, no registry: the kid IS the key. A different issuer's identical
    // claims verify under THEIR did — two self-certifying issuers, zero lookups.
    const other = signAgentCredential(
      { agent_id: "synthetic-travel-agent", allowed_mcc: ["7011"] },
      otherKey,
    );
    expect(verifyAgentCredential(other).issuer_did).toBe(otherKey.did);
    expect(otherKey.did).not.toBe(issuerKey.did);
  });
});

describe("tampered / alg-confused credentials are rejected (never decision input)", () => {
  it("a TAMPERED signature (one char flipped mid-segment) → signature_invalid", () => {
    const [header, payload, signature] = genuine.split(".") as [string, string, string];
    const mid = Math.floor(signature.length / 2);
    const flipped = signature[mid] === "A" ? "B" : "A";
    const tampered = `${header}.${payload}.${signature.slice(0, mid)}${flipped}${signature.slice(mid + 1)}`;
    expectRejection(tampered, "signature_invalid", "does not verify");
  });

  it("a TAMPERED payload (scope widened, signature kept) → signature_invalid", () => {
    const [header, , signature] = genuine.split(".") as [string, string, string];
    const widened = b64url(
      JSON.stringify(claimPayload(issuerKey, { scope: { allowed_mcc: ["7995"] } })),
    );
    expectRejection(`${header}.${widened}.${signature}`, "signature_invalid", "verify");
  });

  it('alg:"none" → alg_rejected, BEFORE any key material is touched', () => {
    const [, payload, signature] = genuine.split(".") as [string, string, string];
    const noneHeader = b64url(JSON.stringify({ alg: "none", kid: issuerKey.did }));
    expectRejection(`${noneHeader}.${payload}.${signature}`, "alg_rejected", "EdDSA");
  });

  it("HS256 substitution → alg_rejected (no algorithm negotiation exists)", () => {
    const [, payload, signature] = genuine.split(".") as [string, string, string];
    const hsHeader = b64url(JSON.stringify({ alg: "HS256", kid: issuerKey.did }));
    expectRejection(`${hsHeader}.${payload}.${signature}`, "alg_rejected", "HS256");
  });

  it("a credential signed by key B but claiming key A's did in the header → signature_invalid", () => {
    // Header kid = A's did (the verifying key); B signed. The self-certifying
    // resolution imports A's key, under which B's signature cannot verify.
    const credential = signClaim(claimPayload(issuerKey), otherKey, {
      alg: "EdDSA",
      kid: issuerKey.did,
    });
    expectRejection(credential, "signature_invalid", "verify");
  });

  it("a canonical but WRONG-LENGTH (65-byte) signature → signature_invalid at the length gate", () => {
    // A 65-byte signature, canonically base64url-encoded, passes the structure
    // and canonical-encoding checks but trips the EXPLICIT Ed25519 length gate
    // (distinct from the tamper path above, which keeps a 64-byte signature —
    // parity with the W1 verifier's separately-tested length gate).
    const [header, payload, signature] = genuine.split(".") as [string, string, string];
    const longSig = Buffer.concat([
      Buffer.from(signature, "base64url"),
      Buffer.from([0]),
    ]).toString("base64url");
    expectRejection(`${header}.${payload}.${longSig}`, "signature_invalid", "64 bytes");
  });
});

describe("malformed credentials are rejected with precise codes", () => {
  it("not a JWS at all → malformed", () => {
    expectRejection("not-a-jws", "malformed", "3-segment");
  });

  it("a non-string credential value → malformed", () => {
    expectRejection(12345, "malformed", "JWS-compact string");
  });

  it("a padded (non-canonical base64url) segment → malformed (malleability closed)", () => {
    expectRejection(`${genuine}=`, "malformed", "canonical unpadded base64url");
  });

  it("extra protected-header parameters (typ) → malformed (closed header, no smuggling)", () => {
    const credential = signClaim(claimPayload(issuerKey), issuerKey, {
      alg: "EdDSA",
      kid: issuerKey.did,
      typ: "JWT",
    });
    expectRejection(credential, "malformed", "exactly");
  });

  it("a kid that is not a did:key → issuer_invalid", () => {
    const credential = signClaim(claimPayload(issuerKey), issuerKey, {
      alg: "EdDSA",
      kid: issuerKey.kid, // the JWKS thumbprint kid, NOT a did:key
    });
    expectRejection(credential, "issuer_invalid", "did:key");
  });

  it("a did:key with invalid base58 → issuer_invalid", () => {
    const credential = signClaim(claimPayload(issuerKey), issuerKey, {
      alg: "EdDSA",
      kid: "did:key:zIOl0", // I, O, l, 0 are not base58btc characters
    });
    expectRejection(credential, "issuer_invalid", "did:key");
  });

  it("issuer claim ≠ signing did:key → issuer_invalid (binding check)", () => {
    const credential = signClaim(
      claimPayload(issuerKey, { issuer: otherKey.did }),
      issuerKey,
    );
    expectRejection(credential, "issuer_invalid", "does not match");
  });

  it("MISSING scope → payload_invalid", () => {
    const claim = claimPayload(issuerKey);
    delete claim["scope"];
    expectRejection(signClaim(claim, issuerKey), "payload_invalid", "exactly");
  });

  it("EMPTY allowed_mcc → payload_invalid (a scope must scope something)", () => {
    const credential = signClaim(
      claimPayload(issuerKey, { scope: { allowed_mcc: [] } }),
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", "non-empty");
  });

  it("a non-4-digit MCC in the scope → payload_invalid", () => {
    const credential = signClaim(
      claimPayload(issuerKey, { scope: { allowed_mcc: ["70"] } }),
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", "4-digit");
  });

  it("an UNKNOWN payload field → payload_invalid (closed claim shape)", () => {
    const credential = signClaim(
      claimPayload(issuerKey, { expires_at: "2027-01-01" }), // expiry is LOCKED OUT of v0.1
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", "exactly");
  });

  it("a wrong credential_type → payload_invalid (no format negotiation)", () => {
    const credential = signClaim(
      claimPayload(issuerKey, { credential_type: "w3c-vc/2.0" }),
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", AGENT_CREDENTIAL_TYPE);
  });

  it("a NON-CANONICAL payload (same content, unsorted keys) → payload_invalid", () => {
    // Identical claim content, but serialized with insertion order ≠ RFC 8785
    // key order — one credential content must have exactly one byte form.
    const claim = claimPayload(issuerKey);
    const unsorted = JSON.stringify({
      scope: claim["scope"],
      issuer: claim["issuer"],
      credential_type: claim["credential_type"],
      agent_id: claim["agent_id"],
    });
    const credential = signRawCredential(
      { alg: "EdDSA", kid: issuerKey.did },
      Buffer.from(unsorted, "utf8"),
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", "canonical");
  });

  it("a non-object payload (JSON array) → payload_invalid", () => {
    const credential = signRawCredential(
      { alg: "EdDSA", kid: issuerKey.did },
      Buffer.from("[]", "utf8"),
      issuerKey,
    );
    expectRejection(credential, "payload_invalid", "JSON object");
  });
});
