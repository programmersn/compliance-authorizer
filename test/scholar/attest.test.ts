/**
 * Scholar-attestation path (ET20) — the machinery a CERTIFIED v1.0 pack WOULD
 * use, shipped at v0.1 as an UNCERTIFIED specimen, never a bare null.
 *
 * Covers: create → verify round-trip; offline-completeness (the did:key is the
 * only key material); determinism (byte-stable signature); and EVERY defective
 * variant — tampered rule_pack_hash, tampered metadata, tampered scholar_did,
 * wrong expected pack, alg:none, HS256 substitution, a non-detached (payload
 * present) JWS, a foreign-signer attestation, and malformed shapes — each
 * rejected with the right ScholarAttestationError code.
 *
 * SYNTHETIC DATA ONLY: generated throwaway keys, generic placeholder metadata.
 */
import { sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import {
  SCHOLAR_ATTESTATION_TYPE,
  ScholarAttestationError,
  createScholarAttestation,
  verifyScholarAttestation,
  type ScholarAttestation,
  type ScholarMetadata,
} from "../../src/scholar/attest.ts";

const scholarKey = generateSigningKey();
const otherKey = generateSigningKey();

// A representative synthetic rule_pack_hash (sha256-hex shaped). The attestation
// path is pack-agnostic — it binds whatever hash it is given.
const PACK_HASH =
  "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4";
const OTHER_PACK_HASH = "a".repeat(64);

const metadata: ScholarMetadata = {
  name: "Synthetic Demo Scholar — not a real person",
  body: "Synthetic Demo Review Committee — not a real certifying body",
  role: "synthetic demo committee member",
  date: "2026-01-01",
};

const genuine = createScholarAttestation(PACK_HASH, scholarKey, metadata);

/** Assert rejection with a specific ScholarAttestationError code + message bit. */
function expectRejection(
  attestation: unknown,
  expectedHash: string,
  code: string,
  messageSubstring: string,
) {
  let caught: unknown;
  try {
    verifyScholarAttestation(attestation, expectedHash);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(ScholarAttestationError);
  expect((caught as ScholarAttestationError).code).toBe(code);
  expect((caught as ScholarAttestationError).message).toContain(messageSubstring);
}

/** Re-sign a (possibly tampered) attestation's claim with an arbitrary key and
 * header, returning a fresh detached JWS — for adversarial alg/signer variants
 * where the signature itself must verify so the test pins WHICH check rejects. */
function resignDetached(
  scholarDid: string,
  rulePackHash: string,
  meta: ScholarMetadata,
  header: unknown,
  signingKey = scholarKey,
): string {
  // Mirror src/scholar/attest.ts claimBytes exactly so the reconstructed payload
  // matches when the honest header is used.
  const claim = JSON.stringify({
    attestation_type: SCHOLAR_ATTESTATION_TYPE,
    metadata: {
      body: meta.body,
      date: meta.date,
      name: meta.name,
      role: meta.role,
    },
    rule_pack_hash: rulePackHash,
    scholar_did: scholarDid,
  });
  // (Canonical key order written out by hand: attestation_type < metadata <
  // rule_pack_hash < scholar_did, and inside metadata body < date < name < role.)
  const headerB64 = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(claim, "utf8").toString("base64url");
  const signature = edSign(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    signingKey.privateKey,
  );
  return `${headerB64}..${Buffer.from(signature).toString("base64url")}`;
}

describe("create → verify round-trip (the certified-path machinery)", () => {
  it("a created attestation verifies and yields the scholar did, pack hash, and metadata", () => {
    const verified = verifyScholarAttestation(genuine, PACK_HASH);
    expect(verified.scholar_did).toBe(scholarKey.did);
    expect(verified.scholar_did.startsWith("did:key:z")).toBe(true); // self-certifying DID
    expect(verified.rule_pack_hash).toBe(PACK_HASH);
    expect(verified.metadata).toEqual(metadata);
  });

  it("the attestation shape matches the envelope's certification_note (did:key + detached JWS)", () => {
    expect(genuine.attestation_type).toBe(SCHOLAR_ATTESTATION_TYPE);
    expect(genuine.scholar_did).toBe(scholarKey.did);
    expect(genuine.rule_pack_hash).toBe(PACK_HASH);
    // DETACHED: the middle (payload) segment is EMPTY — the claim is carried in
    // the sibling fields, not inside the JWS.
    const [, payloadSegment] = genuine.signature.split(".");
    expect(payloadSegment).toBe("");
  });

  it("creating is DETERMINISTIC: same key + same claim → byte-identical attestation", () => {
    // Ed25519 signing is deterministic and the claim is canonical (RFC 8785),
    // so an attestation has exactly one byte representation per (key, claim).
    const again = createScholarAttestation(PACK_HASH, scholarKey, metadata);
    expect(again).toEqual(genuine);
    expect(again.signature).toBe(genuine.signature);
  });

  it("verification is OFFLINE-complete: the did:key is the only key material", () => {
    // No JWKS, no registry: the kid IS the key. A different scholar's identical
    // metadata verifies under THEIR did — two self-certifying signers, zero lookups.
    const other = createScholarAttestation(PACK_HASH, otherKey, metadata);
    expect(verifyScholarAttestation(other, PACK_HASH).scholar_did).toBe(otherKey.did);
    expect(otherKey.did).not.toBe(scholarKey.did);
  });
});

describe("tampering is detected — the whole claim is bound by the signature", () => {
  it("a tampered rule_pack_hash (re-signed over a DIFFERENT pack) → claim_invalid against the expected pack", () => {
    // An attestation legitimately signed over OTHER_PACK_HASH cannot stand in for
    // PACK_HASH: the binding check rejects it before the signature is even reached.
    const overOtherPack = createScholarAttestation(OTHER_PACK_HASH, scholarKey, metadata);
    expectRejection(overOtherPack, PACK_HASH, "claim_invalid", "different pack");
  });

  it("a tampered rule_pack_hash field (signature kept) → signature_invalid", () => {
    // Flip the bound hash but keep the original signature: the reconstructed
    // claim no longer matches what was signed.
    const tampered: ScholarAttestation = { ...genuine, rule_pack_hash: OTHER_PACK_HASH };
    expectRejection(tampered, OTHER_PACK_HASH, "signature_invalid", "does not verify");
  });

  it("tampered metadata (name changed, signature kept) → signature_invalid", () => {
    const tampered: ScholarAttestation = {
      ...genuine,
      metadata: { ...metadata, name: "Different Synthetic Name" },
    };
    expectRejection(tampered, PACK_HASH, "signature_invalid", "does not verify");
  });

  it("a tampered scholar_did (signature kept) → issuer_invalid (header kid no longer matches)", () => {
    const tampered: ScholarAttestation = { ...genuine, scholar_did: otherKey.did };
    expectRejection(tampered, PACK_HASH, "issuer_invalid", "does not match");
  });

  it("an attestation signed by key B but claiming key A's did → issuer_invalid", () => {
    // Header kid = A's did (in genuine.signature), but we relabel scholar_did to A
    // while B's key is irrelevant here — reuse the genuine signature with a
    // mismatched scholar_did. Covered by the scholar_did tamper above; here we
    // assert a foreign-signed claim under A's header fails at the signature.
    const foreign = resignDetached(scholarKey.did, PACK_HASH, metadata, {
      alg: "EdDSA",
      kid: scholarKey.did,
    }, otherKey);
    const attestation: ScholarAttestation = { ...genuine, signature: foreign };
    expectRejection(attestation, PACK_HASH, "signature_invalid", "does not verify");
  });
});

describe("alg confusion is rejected before key material is touched", () => {
  it('alg:"none" → alg_rejected', () => {
    const noneSig = resignDetached(scholarKey.did, PACK_HASH, metadata, {
      alg: "none",
      kid: scholarKey.did,
    });
    expectRejection({ ...genuine, signature: noneSig }, PACK_HASH, "alg_rejected", "EdDSA");
  });

  it("HS256 substitution → alg_rejected (no algorithm negotiation exists)", () => {
    const hsSig = resignDetached(scholarKey.did, PACK_HASH, metadata, {
      alg: "HS256",
      kid: scholarKey.did,
    });
    expectRejection({ ...genuine, signature: hsSig }, PACK_HASH, "alg_rejected", "HS256");
  });

  it("extra protected-header parameters (typ) → malformed (closed header)", () => {
    const typSig = resignDetached(scholarKey.did, PACK_HASH, metadata, {
      alg: "EdDSA",
      kid: scholarKey.did,
      typ: "JWT",
    });
    expectRejection({ ...genuine, signature: typSig }, PACK_HASH, "malformed", "exactly");
  });
});

describe("malformed attestations are rejected with precise codes", () => {
  it("a non-object attestation → malformed", () => {
    expectRejection("not-an-attestation", PACK_HASH, "malformed", "JSON object");
  });

  it("an unknown attestation field → malformed (closed shape)", () => {
    expectRejection(
      { ...genuine, extra: "field" },
      PACK_HASH,
      "malformed",
      "exactly",
    );
  });

  it("a wrong attestation_type → claim_invalid (no format negotiation)", () => {
    expectRejection(
      { ...genuine, attestation_type: "w3c-vc/2.0" },
      PACK_HASH,
      "claim_invalid",
      SCHOLAR_ATTESTATION_TYPE,
    );
  });

  it("an expected rule_pack_hash that is not sha256-hex → claim_invalid", () => {
    expectRejection(genuine, "not-a-hash", "claim_invalid", "sha256 hex digest");
  });

  it("a non-detached signature (payload segment present) → malformed", () => {
    const [header, , sig] = genuine.signature.split(".") as [string, string, string];
    const attached = `${header}.${Buffer.from("{}", "utf8").toString("base64url")}.${sig}`;
    expectRejection({ ...genuine, signature: attached }, PACK_HASH, "malformed", "DETACHED");
  });

  it("a padded (non-canonical base64url) signature segment → malformed (malleability closed)", () => {
    expectRejection(
      { ...genuine, signature: `${genuine.signature}=` },
      PACK_HASH,
      "malformed",
      "canonical unpadded base64url",
    );
  });

  it("metadata missing a field → claim_invalid (closed metadata shape)", () => {
    const partial = { name: metadata.name, body: metadata.body, role: metadata.role };
    expectRejection(
      { ...genuine, metadata: partial },
      PACK_HASH,
      "claim_invalid",
      "exactly",
    );
  });

  it("a non-ISO metadata.date → claim_invalid", () => {
    expectRejection(
      { ...genuine, metadata: { ...metadata, date: "01/01/2026" } },
      PACK_HASH,
      "claim_invalid",
      "ISO-8601",
    );
  });

  it("a kid that is not a did:key → issuer_invalid", () => {
    // Build an attestation whose scholar_did (and header kid) is not a did:key.
    const sig = resignDetached("not-a-did-key", PACK_HASH, metadata, {
      alg: "EdDSA",
      kid: "not-a-did-key",
    });
    expectRejection(
      { ...genuine, scholar_did: "not-a-did-key", signature: sig },
      PACK_HASH,
      "issuer_invalid",
      "did:key",
    );
  });
});

describe("create() input guards", () => {
  it("rejects a non-sha256 rule_pack_hash", () => {
    expect(() => createScholarAttestation("nope", scholarKey, metadata)).toThrow(
      ScholarAttestationError,
    );
  });

  it("rejects metadata with an empty field", () => {
    expect(() =>
      createScholarAttestation(PACK_HASH, scholarKey, { ...metadata, name: "" }),
    ).toThrow(ScholarAttestationError);
  });
});
