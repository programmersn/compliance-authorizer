/**
 * The UNCERTIFIED scholar-attestation SPECIMEN (ET20): a v0.1 ships this labeled
 * placeholder INSTEAD of a real certified attestation — never a bare null.
 *
 * This test is the drift guard + the honesty guard:
 *   - the COMMITTED examples/scholar-attestation.specimen.json equals a fresh
 *     deterministic build (so the file can never silently rot vs the code),
 *   - the inner attestation VERIFIES offline against the CURRENT rule pack hash
 *     (so a pack bump that forgets to regenerate the specimen fails CI),
 *   - the specimen is UNCERTIFIED and carries the verbatim honesty wording,
 *   - NO real scholar or certifying-body name appears (public-content guard).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { verifyScholarAttestation } from "../../src/scholar/attest.ts";
import {
  SPECIMEN_METADATA,
  SPECIMEN_STATEMENT,
  buildScholarAttestationSpecimen,
  loadSpecimenScholarKey,
} from "../../src/scholar/specimen.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const packPath = join(repoRoot, "rule-packs", "shariah", "0.1.1.json");
const specimenPath = join(repoRoot, "examples", "scholar-attestation.specimen.json");

const loadedPack = loadRulePackFile(packPath);
const committed = JSON.parse(readFileSync(specimenPath, "utf8")) as Record<
  string,
  unknown
>;

describe("the committed UNCERTIFIED specimen is byte-reproducible and verifies", () => {
  it("the committed file equals a fresh deterministic build for the CURRENT pack hash", () => {
    const fresh = buildScholarAttestationSpecimen(loadedPack.hash);
    // Round-trip the fresh build through JSON so the comparison is on the same
    // (parsed) shape the committed file deserializes to.
    expect(committed).toEqual(JSON.parse(JSON.stringify(fresh)));
  });

  it("a bare regeneration is deterministic (same bytes twice)", () => {
    const a = buildScholarAttestationSpecimen(loadedPack.hash);
    const b = buildScholarAttestationSpecimen(loadedPack.hash);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("the specimen's inner attestation VERIFIES against the current rule pack hash", () => {
    const attestation = (committed["attestation"] ?? {}) as Record<string, unknown>;
    const verified = verifyScholarAttestation(attestation, loadedPack.hash);
    expect(verified.rule_pack_hash).toBe(loadedPack.hash);
    expect(verified.scholar_did).toBe(loadedSpecimenDid());
    expect(verified.metadata).toEqual(SPECIMEN_METADATA);
  });

  it("the committed rule_pack_hash matches the live pack (a pack bump must regenerate)", () => {
    const attestation = committed["attestation"] as Record<string, unknown>;
    expect(attestation["rule_pack_hash"]).toBe(loadedPack.hash);
  });
});

describe("the specimen is honestly labeled UNCERTIFIED (the guard)", () => {
  it('status is "uncertified" and the statement is the verbatim honesty wording', () => {
    expect(committed["status"]).toBe("uncertified");
    expect(committed["statement"]).toBe(SPECIMEN_STATEMENT);
    expect(committed["statement"]).toContain(
      "not a fatwa / not certified / not production advice",
    );
  });

  it("the copy stays future-conditional (a certified pack WOULD carry this)", () => {
    expect(String(committed["statement"])).toContain("would carry");
    // No present-tense certification claim.
    expect(String(committed["statement"])).not.toMatch(/\bis certified\b/);
  });

  it("metadata is explicitly SYNTHETIC — no real scholar or institution named", () => {
    const attestation = committed["attestation"] as Record<string, unknown>;
    const meta = attestation["metadata"] as Record<string, string>;
    expect(meta["name"]).toContain("Synthetic Demo Scholar");
    expect(meta["name"]).toContain("not a real person");
    expect(meta["body"]).toContain("not a real certifying body");
  });
});

/** The did:key the committed throwaway specimen key resolves to. */
function loadedSpecimenDid(): string {
  return loadSpecimenScholarKey().did;
}
