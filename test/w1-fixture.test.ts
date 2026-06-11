/**
 * THE W1 GATE (ET9, T-02 abort anchor): POST /authorize → signed evidence →
 * the STANDALONE offline verifier (spawned as a real child process, zero
 * server contact) accepts it — and rejects every tampered variant.
 *
 * This is the first CI gate. If this file is red, W1 is not done.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildJwks, generateSigningKey } from "../src/crypto/keys.ts";
import { buildEnvelope, signEnvelope } from "../src/evidence/envelope.ts";
import { evaluate } from "../src/rules/evaluator.ts";
import { loadRulePackFile } from "../src/rules/loader.ts";
import { buildServer } from "../src/server.ts";
import { verifyEvidence } from "../verifier/verify.mjs";
import { fixedEnvelopeDeps } from "./fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifierPath = join(repoRoot, "verifier", "verify.mjs");
const packPath = join(repoRoot, "rule-packs", "shariah", "0.1.0.json");

const signingKey = generateSigningKey();
const loadedPack = loadRulePackFile(packPath);
const app = buildServer({ loadedPacks: [loadedPack], signingKey });

let workDir: string;
let evidencePath: string;
let jwksPath: string;
let fixturePackPath: string;
let evidenceJws: string;

/** UC1 fixture: an agent books a casino-hotel → DENY (MAYSIR). Synthetic data only. */
const casinoHotelIntent = {
  profile: "shariah-v0.1",
  merchant: {
    name: "casino-hotel",
    mcc: "7011",
    country: "GB",
    attributes: ["casino", "gambling"],
  },
  amount: { value: 389.99, currency: "GBP" },
};

function runVerifier(args: string[]): { status: number | null; stdout: string } {
  const result = spawnSync(process.execPath, [verifierPath, ...args], {
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout + result.stderr };
}

const verifierArgs = (evidence: string): string[] => [
  "--evidence", evidence,
  "--jwks", jwksPath,
  "--pack", fixturePackPath,
];

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), "w1-fixture-"));
  evidencePath = join(workDir, "evidence.jws");
  jwksPath = join(workDir, "jwks.json");
  fixturePackPath = join(workDir, "pack.json");

  const response = await app.inject({
    method: "POST",
    url: "/authorize",
    payload: casinoHotelIntent,
  });
  expect(response.statusCode).toBe(200);
  const body = response.json<{ decision: string; evidence_artifact: string }>();
  expect(body.decision).toBe("deny");
  evidenceJws = body.evidence_artifact;

  writeFileSync(evidencePath, evidenceJws, "utf8");
  writeFileSync(jwksPath, JSON.stringify(buildJwks([signingKey.publicJwk]), null, 2), "utf8");
  copyFileSync(packPath, fixturePackPath);
});

afterAll(async () => {
  await app.close();
  rmSync(workDir, { recursive: true, force: true });
});

describe("W1 gate: sign → offline-verify round-trip", () => {
  it("the offline verifier PASSES genuine evidence (exit 0, zero server contact)", () => {
    const { status, stdout } = runVerifier(verifierArgs(evidencePath));
    expect(stdout).toContain("RESULT: PASS");
    expect(stdout).toContain('decision "deny"');
    expect(stdout).toContain("UNCERTIFIED"); // honesty signal survives into the CLI
    // Trust anchor: the CLI prints the verifying key's fingerprint for
    // out-of-band comparison against the issuer's published did:key.
    expect(stdout).toContain(signingKey.did);
    expect(stdout).toContain("TRUST ANCHOR");
    // Honesty scope line: PASS = authenticity/integrity, not decision replay.
    expect(stdout).toContain("does NOT re-run the rule evaluator");
    expect(status).toBe(0);
  });

  it("also passes WITHOUT the pack (signature + canonical form + intent hash alone)", () => {
    const { status, stdout } = runVerifier([
      "--evidence", evidencePath,
      "--jwks", jwksPath,
    ]);
    expect(stdout).toContain("RESULT: PASS");
    expect(status).toBe(0);
  });

  it("FAILS evidence whose decision was flipped deny → allow (exit 1)", () => {
    const [header, payloadB64, signature] = evidenceJws.split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    envelope["decision"] = "allow";
    envelope["reason_codes"] = [];
    // Re-encode in canonical key order so ONLY the signature check can catch it.
    const sortedJson = JSON.stringify(
      Object.fromEntries(Object.entries(envelope).sort(([a], [b]) => (a < b ? -1 : 1))),
    );
    const tamperedPath = join(workDir, "tampered-decision.jws");
    writeFileSync(
      tamperedPath,
      `${header}.${Buffer.from(sortedJson, "utf8").toString("base64url")}.${signature}`,
      "utf8",
    );

    const { status, stdout } = runVerifier(verifierArgs(tamperedPath));
    expect(stdout).toContain("RESULT: FAIL");
    expect(status).toBe(1);
  });

  it("FAILS evidence with a corrupted signature (exit 1)", () => {
    const [header, payloadB64, signature] = evidenceJws.split(".") as [string, string, string];
    const mid = Math.floor(signature.length / 2);
    const flipped = signature[mid] === "A" ? "B" : "A";
    const tamperedPath = join(workDir, "tampered-signature.jws");
    writeFileSync(
      tamperedPath,
      `${header}.${payloadB64}.${signature.slice(0, mid)}${flipped}${signature.slice(mid + 1)}`,
      "utf8",
    );

    const { status, stdout } = runVerifier(verifierArgs(tamperedPath));
    expect(stdout).toContain("RESULT: FAIL");
    expect(status).toBe(1);
  });

  it('FAILS an alg:"none" artifact (exit 1)', () => {
    const [, payloadB64] = evidenceJws.split(".") as [string, string, string];
    const noneHeader = Buffer.from(
      JSON.stringify({ alg: "none", kid: signingKey.kid }),
      "utf8",
    ).toString("base64url");
    const nonePath = join(workDir, "alg-none.jws");
    writeFileSync(nonePath, `${noneHeader}.${payloadB64}.${Buffer.from("x").toString("base64url")}`, "utf8");

    const { status, stdout } = runVerifier(verifierArgs(nonePath));
    expect(stdout).toContain("RESULT: FAIL");
    expect(stdout).toContain("EdDSA");
    expect(status).toBe(1);
  });

  it("FAILS when verified against a DIFFERENT pack than the one cited (exit 1)", () => {
    const otherPackPath = join(workDir, "other-pack.json");
    const pack = JSON.parse(readFileSync(packPath, "utf8")) as {
      rules: { all_of: { value: unknown }[] }[];
    };
    // One rule threshold nudged — content change ⇒ different rule_pack_hash.
    const mixedRule = pack.rules.at(-1);
    mixedRule!.all_of[0]!.value = 0.33;
    writeFileSync(otherPackPath, JSON.stringify(pack, null, 2), "utf8");

    const { status, stdout } = runVerifier([
      "--evidence", evidencePath,
      "--jwks", jwksPath,
      "--pack", otherPackPath,
    ]);
    expect(stdout).toContain("RESULT: FAIL");
    expect(status).toBe(1);
  });
});

describe("verifier pack-consistency sub-branches (id/version + the D12 evaluator seam)", () => {
  // These two branches sit AFTER the signature, canonical-form and intent-hash
  // checks, so they are only reachable with a genuinely-signed, canonical
  // envelope whose rule_pack_hash matches the supplied pack. We build a correct
  // envelope, mutate exactly ONE cited field, and RE-SIGN — so the earlier
  // checks all pass and the pack-hash check is the first (and only) failure.
  // rule_pack_hash itself stays the real pack's hash (it hashes the PACK, not
  // the envelope), so the hash sub-branch passes and a later sub-branch fires.
  const signEnvelopeWithField = (overrides: Record<string, unknown>): string => {
    const evaluation = evaluate(casinoHotelIntent, loadedPack.pack);
    const envelope = buildEnvelope(
      casinoHotelIntent,
      evaluation,
      loadedPack,
      fixedEnvelopeDeps,
    );
    return signEnvelope({ ...envelope, ...overrides }, signingKey);
  };

  it("FAILS at pack-hash when rule_pack_id disagrees with the (correctly-hashed) pack", () => {
    const jws = signEnvelopeWithField({ rule_pack_id: "not-the-shariah-pack" });
    const result = verifyEvidence({
      jws,
      jwks: buildJwks([signingKey.publicJwk]),
      pack: loadedPack.pack,
    });
    expect(result.ok).toBe(false);
    const check = result.checks.find((c) => c.id === "pack-hash");
    expect(check?.ok).toBe(false);
    // The hash sub-branch passed; the id/version sub-branch is what caught it.
    expect(check?.detail).toContain("id/version");
  });

  it("FAILS at the D12 seam when evaluator_version disagrees with the pack's required_evaluator_version", () => {
    // The certification-invalidating case: a hash-matching pack whose pinned
    // evaluator semantics differ from the evaluator that produced the envelope.
    const jws = signEnvelopeWithField({ evaluator_version: "0.9.9" });
    const result = verifyEvidence({
      jws,
      jwks: buildJwks([signingKey.publicJwk]),
      pack: loadedPack.pack,
    });
    expect(result.ok).toBe(false);
    const check = result.checks.find((c) => c.id === "pack-hash");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain("evaluator_version");
    expect(check?.detail).toContain("D12 seam");
    // Everything before pack-hash must have PASSED — otherwise we'd be asserting
    // reachability of the wrong branch (a green-but-meaningless test).
    expect(result.checks.find((c) => c.id === "signature")?.ok).toBe(true);
    expect(result.checks.find((c) => c.id === "intent-hash")?.ok).toBe(true);
  });
});

describe("verifier input errors are operator errors, never verification verdicts", () => {
  it("exits 2 (not 1) with INPUT ERROR when the evidence file is missing", () => {
    const { status, stdout } = runVerifier([
      "--evidence", join(workDir, "does-not-exist.jws"),
      "--jwks", jwksPath,
    ]);
    expect(status).toBe(2);
    expect(stdout).toContain("INPUT ERROR");
    expect(stdout).not.toContain("RESULT: FAIL");
  });

  it("exits 2 (not 1) when the JWKS file is not valid JSON", () => {
    const badJwksPath = join(workDir, "bad-jwks.json");
    writeFileSync(badJwksPath, "{ not json", "utf8");
    const { status, stdout } = runVerifier([
      "--evidence", evidencePath,
      "--jwks", badJwksPath,
    ]);
    expect(status).toBe(2);
    expect(stdout).toContain("INPUT ERROR");
  });

  it("exits 2 with a usage message when invoked with no arguments", () => {
    // Missing required --evidence/--jwks is an OPERATOR error (exit 2), printed
    // before anything is verified — never exit 1 (a verification verdict).
    const { status, stdout } = runVerifier([]);
    expect(status).toBe(2);
    expect(stdout).toContain("usage:");
    expect(stdout).not.toContain("RESULT:");
  });

  it("exits 2 (not 1) on an unknown flag — parseArgs throws, but bad usage is an operator error", () => {
    // parseArgs (strict mode) THROWS on an unknown flag / stray positional / a
    // value-option with no value. That throw sits before the read/parse try/catch,
    // so without its own guard Node exits 1 — the "NOT valid evidence" VERDICT code
    // — for a mere typo, which automation chaining the verifier would misread.
    const { status, stdout } = runVerifier([
      "--evidence", evidencePath,
      "--jwks", jwksPath,
      "--bogus-flag",
    ]);
    expect(status).toBe(2);
    expect(stdout).toContain("INPUT ERROR");
    expect(stdout).not.toContain("RESULT:");
  });
});

describe("verifier independence (zero-trust property is structural, not aspirational)", () => {
  it("verify.mjs imports node built-ins ONLY — nothing from src/, no packages", () => {
    const source = readFileSync(verifierPath, "utf8");
    const importSpecifiers = [...source.matchAll(/from\s+"([^"]+)"/g)].map(
      (match) => match[1],
    );
    expect(importSpecifiers.length).toBeGreaterThan(0);
    for (const specifier of importSpecifiers) {
      expect(specifier).toMatch(/^node:/);
    }
  });
});
