/**
 * CREDENTIALED OFFLINE ROUND-TRIP (ET16/ET17 gate): a two-layer signed envelope
 * (a) VERIFIES offline via verifier/verify.mjs and (b) REPLAYS to the exact same
 * decision via scripts/replay.ts — both spawned as REAL child processes with
 * zero server contact, exactly as an outsider runs them. The credential's
 * did:key issuer is self-certifying, so the replay leg re-verifies the
 * credential signature offline with NO inputs beyond the envelope + pack + jwks
 * files on disk.
 *
 * Also pins the dishonest-signer case the two-tool split exists for: an
 * envelope whose embedded credential was TAMPERED and then RE-SIGNED with the
 * engine key is AUTHENTIC (verify.mjs PASS — the signature covers those exact
 * bytes) yet conclusively NOT REPRODUCED (an honest engine refuses such an
 * intent and never signs a decision for it).
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import { buildEnvelope, signEnvelope } from "../../src/evidence/envelope.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { buildServer } from "../../src/server.ts";
import { AGENT_SCOPE_EXCEEDED, decideIntent } from "../../src/vc/enforce.ts";
import { signAgentCredential } from "../../src/vc/mint.ts";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const verifierPath = join(repoRoot, "verifier", "verify.mjs");
const replayPath = join(repoRoot, "scripts", "replay.ts");
const packPath = join(repoRoot, "rule-packs", "shariah", "0.1.1.json");

const loadedPack = loadRulePackFile(packPath);
const issuerKey = generateSigningKey(); // credential issuer (synthetic agent's)
const signingKey = generateSigningKey(); // evidence issuer (the engine's)
const app = buildServer({
  loadedPacks: [loadedPack],
  signingKey,
  envelopeDeps: fixedEnvelopeDeps,
});

/** In-scope and out-of-scope synthetic credentials for the hotel MCC 7011. */
const inScopeCredential = signAgentCredential(
  { agent_id: "synthetic-travel-agent", allowed_mcc: ["7011"] },
  issuerKey,
);
const outOfScopeCredential = signAgentCredential(
  { agent_id: "synthetic-travel-agent", allowed_mcc: ["5411"] },
  issuerKey,
);

const credentialedIntent = (credential: string): Record<string, unknown> => ({
  profile: "shariah-v0.1",
  merchant: { name: "seaside-hotel", mcc: "7011", attributes: [] },
  amount: { value: 180, currency: "EUR" },
  agent_credential: credential,
});

function runVerifier(args: string[]): { status: number | null; out: string } {
  const result = spawnSync(process.execPath, [verifierPath, ...args], {
    encoding: "utf8",
  });
  return { status: result.status, out: result.stdout + result.stderr };
}

function runReplay(args: string[]): { status: number | null; out: string } {
  const result = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--no-warnings", replayPath, ...args],
    { encoding: "utf8" },
  );
  return { status: result.status, out: result.stdout + result.stderr };
}

let workDir: string;
let jwksPath: string;
let fixturePackPath: string;
let allowEvidencePath: string; //   scope-allow → pack-allow → "allow"
let denyEvidencePath: string; //    scope-deny  → "deny" [AGENT_SCOPE_EXCEEDED]
let tamperedEvidencePath: string; // invalid credential, envelope RE-SIGNED

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), "vc-roundtrip-"));
  jwksPath = join(workDir, "jwks.json");
  fixturePackPath = join(workDir, "pack.json");
  allowEvidencePath = join(workDir, "allow.evidence.jws");
  denyEvidencePath = join(workDir, "scope-deny.evidence.jws");
  tamperedEvidencePath = join(workDir, "tampered-credential.evidence.jws");

  writeFileSync(
    jwksPath,
    JSON.stringify(buildJwks([signingKey.publicJwk]), null, 2),
    "utf8",
  );
  copyFileSync(packPath, fixturePackPath);

  // (1) The two genuine credentialed envelopes, served by the real route.
  for (const [path, credential, decision, codes] of [
    [allowEvidencePath, inScopeCredential, "allow", []],
    [denyEvidencePath, outOfScopeCredential, "deny", [AGENT_SCOPE_EXCEEDED]],
  ] as const) {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: credentialedIntent(credential),
    });
    expect(response.statusCode).toBe(200);
    const body = response.json<{
      decision: string;
      reason_codes: string[];
      evidence_artifact: string;
    }>();
    expect(body.decision).toBe(decision);
    expect(body.reason_codes).toEqual([...codes]);
    writeFileSync(path, body.evidence_artifact, "utf8");
  }

  // (2) The dishonest-signer artifact: tamper the credential INSIDE the intent
  // (one mid-signature char flips → the credential no longer verifies), keep
  // the decision an honest engine produced for the VALID credential, and
  // RE-SIGN the whole envelope with the engine key. intent_hash is recomputed
  // over the tampered intent, so every authenticity check passes — only replay
  // can name the defect.
  const evaluation = decideIntent(
    credentialedIntent(inScopeCredential),
    loadedPack.pack,
  );
  const [ch, cp, cs] = inScopeCredential.split(".") as [string, string, string];
  const mid = Math.floor(cs.length / 2);
  const flipped = cs[mid] === "A" ? "B" : "A";
  const brokenCredential = `${ch}.${cp}.${cs.slice(0, mid)}${flipped}${cs.slice(mid + 1)}`;
  const tamperedEnvelope = buildEnvelope(
    credentialedIntent(brokenCredential),
    evaluation,
    loadedPack,
    fixedEnvelopeDeps,
  );
  writeFileSync(tamperedEvidencePath, signEnvelope(tamperedEnvelope, signingKey), "utf8");
});

afterAll(async () => {
  await app.close();
  rmSync(workDir, { recursive: true, force: true });
});

describe("credentialed envelopes round-trip offline: verify.mjs PASS + replay REPRODUCED", () => {
  it("scope-allow envelope: offline verifier PASSES (exit 0, decision allow)", () => {
    const { status, out } = runVerifier([
      "--evidence", allowEvidencePath,
      "--jwks", jwksPath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: PASS");
    expect(out).toContain('decision "allow"');
    expect(out).toContain("UNCERTIFIED");
    expect(status).toBe(0);
  });

  it("scope-allow envelope: offline replay REPRODUCES (exit 0) — the scope layer re-derives", () => {
    const { status, out } = runReplay([
      "--evidence", allowEvidencePath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain('decision "allow"');
    expect(status).toBe(0);
  });

  it("scope-DENY envelope: offline verifier PASSES (a scope-exceeded deny is valid signed evidence)", () => {
    const { status, out } = runVerifier([
      "--evidence", denyEvidencePath,
      "--jwks", jwksPath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: PASS");
    expect(out).toContain('decision "deny"');
    expect(out).toContain(AGENT_SCOPE_EXCEEDED);
    expect(status).toBe(0);
  });

  it("scope-DENY envelope: offline replay re-derives deny + AGENT_SCOPE_EXCEEDED exactly (exit 0)", () => {
    const { status, out } = runReplay([
      "--evidence", denyEvidencePath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain('decision "deny"');
    expect(out).toContain(AGENT_SCOPE_EXCEEDED);
    expect(status).toBe(0);
  });

  it("scope-DENY envelope with --jwks: REPRODUCED and AUTHENTIC in one verdict (exit 0)", () => {
    const { status, out } = runReplay([
      "--evidence", denyEvidencePath,
      "--pack", fixturePackPath,
      "--jwks", jwksPath,
    ]);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain("AUTHENTICITY (--jwks): PASS");
    expect(status).toBe(0);
  });
});

describe("tampered-credential-then-RE-SIGNED: authentic bytes, conclusively NOT reproduced", () => {
  it("verify.mjs PASSES it — authenticity says nothing about the embedded credential", () => {
    const { status, out } = runVerifier([
      "--evidence", tamperedEvidencePath,
      "--jwks", jwksPath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: PASS"); // the engine key really signed these bytes
    expect(status).toBe(0);
  });

  it("replay names it: NOT REPRODUCED, invalid agent credential — a verdict (exit 1), not an input error", () => {
    const { status, out } = runReplay([
      "--evidence", tamperedEvidencePath,
      "--pack", fixturePackPath,
    ]);
    expect(out).toContain("RESULT: NOT REPRODUCED");
    expect(out).toContain("INVALID agent credential");
    expect(out).toContain("never signs a decision");
    expect(out).not.toContain("INPUT ERROR"); // a verdict, never exit-2 wording
    expect(out).not.toContain("could not be attempted"); // distinct from the D12 unknown
    expect(status).toBe(1);
  });

  it("replay --jwks: AUTHENTIC yet NOT reproduced → combined exit 1", () => {
    const { status, out } = runReplay([
      "--evidence", tamperedEvidencePath,
      "--pack", fixturePackPath,
      "--jwks", jwksPath,
    ]);
    expect(out).toContain("RESULT: NOT REPRODUCED");
    expect(out).toContain("AUTHENTICITY (--jwks): PASS"); // both properties, separately
    expect(status).toBe(1); // exit 0 requires BOTH
  });
});

describe("POST /verify reports the same split for credentialed artifacts (served == offline)", () => {
  function verifyArtifact(path: string) {
    return app.inject({
      method: "POST",
      url: "/verify",
      payload: { evidence_artifact: readFileSync(path, "utf8").trim() },
    });
  }

  it("the genuine scope-deny artifact → valid:true, reproducibility.reproduced:true", async () => {
    const response = await verifyArtifact(denyEvidencePath);
    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(true);
    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r["replayed"]).toBe(true);
    expect(r["reproduced"]).toBe(true);
    expect(r["decision"]).toBe("deny");
    expect(r["reason_codes"]).toEqual([AGENT_SCOPE_EXCEEDED]);
  });

  it("the tampered-credential artifact → valid:true BUT agent_credential_valid:false, reproduced:false", async () => {
    const response = await verifyArtifact(tamperedEvidencePath);
    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(true); // authentic — the engine key signed it
    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r["agent_credential_valid"]).toBe(false);
    expect(r["replayed"]).toBe(true);
    expect(r["reproduced"]).toBe(false); // conclusive, never null
    expect(r["detail"]).toContain("agent credential");
    expect(r["detail"]).toContain("never signs a decision");
  });
});
