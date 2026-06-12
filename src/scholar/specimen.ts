/**
 * The UNCERTIFIED scholar-attestation SPECIMEN (ET20).
 *
 * This is the labeled placeholder a v0.1 ships INSTEAD of a real certified
 * attestation — never a bare null. It exercises the full createScholarAttestation
 * / verifyScholarAttestation path (src/scholar/attest.ts) over the CURRENT rule
 * pack, but with:
 *   - a synthetic THROWAWAY scholar key (embedded below, committed on purpose),
 *   - metadata populated with explicitly SYNTHETIC placeholders — NO real
 *     scholar or certifying-body name anywhere,
 *   - an "uncertified" status and a verbatim honesty statement.
 *
 * The forward-projection is explicit: a CERTIFIED v1.0 pack WOULD carry a real
 * scholar's did:key and this same detached-JWS shape over the pack hash. This
 * specimen demonstrates the machinery WITHOUT making any certification claim.
 *
 * BYTE-REPRODUCIBLE, exactly like examples/casino-hotel.evidence.jws:
 *   - Ed25519 (RFC 8032) signing is deterministic,
 *   - the signed claim is RFC 8785 canonical bytes,
 *   - the scholar key is IMPORTED from a fixed committed JWK (never generated),
 *   - the rule_pack_hash is read from the committed pack.
 * So scripts/build-scholar-specimen.ts rewrites identical bytes every run, and
 * test/scholar/specimen.test.ts asserts the committed file equals a fresh build.
 */
import {
  importPrivateJwk,
  type PrivateJwk,
  type SigningKey,
} from "../crypto/keys.ts";
import {
  createScholarAttestation,
  type ScholarAttestation,
  type ScholarMetadata,
} from "./attest.ts";

/**
 * THROWAWAY demo scholar PRIVATE key — committed on purpose, like
 * examples/issuer.demo.jwk.json. It signs NOTHING but this synthetic UNCERTIFIED
 * specimen, has no value, is not a production key, and must never be reused. A
 * certified pack's scholar key would live out-of-band, never in source.
 */
const SPECIMEN_SCHOLAR_JWK: PrivateJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "qDbQgkULyakwHVpkhdB0zjjbiYgwUqEhgIvuS8foY7o",
  kid: "1lYg5IPiwe4WjWYH4OhlO8aF5My7gHao9R0uPe0-tOU",
  alg: "EdDSA",
  use: "sig",
  d: "VI_wuddI_6ZRYqYkLYTnK-3F1T-l44rqsqmNRgB-r2A",
};

/** Import the committed throwaway scholar key (never generate one). */
export function loadSpecimenScholarKey(): SigningKey {
  return importPrivateJwk(SPECIMEN_SCHOLAR_JWK);
}

/**
 * SYNTHETIC metadata — placeholders that announce themselves as not-real. No
 * named real scholar or institution appears anywhere (public-content guard).
 */
export const SPECIMEN_METADATA: ScholarMetadata = {
  name: "Synthetic Demo Scholar — not a real person",
  body: "Synthetic Demo Review Committee — not a real certifying body",
  role: "synthetic demo committee member (illustrative only)",
  date: "2026-01-01",
};

/**
 * Verbatim honesty statement carried alongside the specimen. Uses the locked
 * honesty wording and stays future-conditional — this is what a certified pack
 * WOULD carry, never a claim that this demo IS certified.
 */
export const SPECIMEN_STATEMENT =
  "synthetic demo rule pack — not a fatwa / not certified / not production advice. " +
  "This is a structural specimen of the scholar-attestation path; a certified " +
  "v1.0 pack would carry a real scholar's did:key and a detached signature over " +
  "this rule pack's hash in this shape.";

/**
 * The committed specimen wraps the attestation in an UNCERTIFIED frame: the
 * status label, the honesty statement, and the inner (structurally valid)
 * attestation produced by the real path. The status makes the demo's nature
 * unmissable to any reader of the file or the rendered surface.
 */
export interface ScholarAttestationSpecimen {
  /** Always "uncertified" — this is a specimen, not a certified ruling. */
  status: "uncertified";
  /** The verbatim honesty statement (locked wording, future-conditional). */
  statement: string;
  /** The structurally valid attestation produced by createScholarAttestation. */
  attestation: ScholarAttestation;
}

/**
 * Build the UNCERTIFIED specimen for a given rule_pack_hash. Pure given the
 * committed key + the hash: no I/O, no randomness, no clock — so the bytes are
 * reproducible. The inner attestation is a REAL, verifiable attestation; only
 * its synthetic key + placeholder metadata + the surrounding uncertified frame
 * mark it as a demo.
 */
export function buildScholarAttestationSpecimen(
  rulePackHash: string,
): ScholarAttestationSpecimen {
  const attestation = createScholarAttestation(
    rulePackHash,
    loadSpecimenScholarKey(),
    SPECIMEN_METADATA,
  );
  return {
    status: "uncertified",
    statement: SPECIMEN_STATEMENT,
    attestation,
  };
}
