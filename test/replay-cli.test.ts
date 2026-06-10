/**
 * scripts/replay.ts CLI exit-code discipline (mirrors verifier/verify.mjs):
 *   0 = success — REPRODUCED (and, with --jwks, also AUTHENTIC),
 *   1 = a negative verdict (NOT reproduced / unknown, or --jwks authenticity FAIL),
 *   2 = operator/input error (nothing was replayed or verified).
 *
 * The load-bearing case here is the rule_pack_hash guard: id+version do NOT pin
 * pack CONTENT, so a content-modified pack carrying the cited id/version must be
 * rejected as an operator error (exit 2), NEVER replayed against — otherwise the
 * tool can emit a false REPRODUCED (exit 0) against bytes the envelope never
 * cited. The route (POST /verify) is immune because verify.mjs folds the hash
 * into authenticity; this standalone CLI needs its own guard.
 *
 * The OPTIONAL --jwks combined verdict is also exercised below: bare replay
 * stays reproducibility-only (exit 0 = reproduced, loudly labelled "authenticity
 * NOT checked"); with --jwks, exit 0 additionally requires the artifact to be
 * authentic, so automation reading only the exit code cannot mistake a bare
 * "reproduced" for "valid evidence."
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { canonicalize } from "../src/crypto/canonicalize.ts";
import { sha256Hex } from "../src/crypto/hash.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const replayScript = join(repoRoot, "scripts", "replay.ts");
const evidencePath = join(repoRoot, "examples", "casino-hotel.evidence.jws");
const genuinePackPath = join(repoRoot, "examples", "pack.json");
const genuineJwksPath = join(repoRoot, "examples", "jwks.json");

interface Pack {
  id: string;
  version: string;
  rules: { id: string }[];
  [k: string]: unknown;
}

let workDir: string;

function runReplay(
  packPath: string,
  jwksPath?: string,
): { status: number | null; out: string } {
  const args = [
    "--experimental-strip-types",
    "--no-warnings",
    replayScript,
    "--evidence",
    evidencePath,
    "--pack",
    packPath,
  ];
  if (jwksPath !== undefined) args.push("--jwks", jwksPath);
  const result = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { status: result.status, out: result.stdout + result.stderr };
}

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "replay-cli-"));
});

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe("replay CLI exit discipline", () => {
  it("genuine evidence + the cited pack → REPRODUCED, exit 0", () => {
    const { status, out } = runReplay(genuinePackPath);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain('decision "deny"');
    expect(out).toContain("UNCERTIFIED");
    expect(status).toBe(0);
  });

  it("a CONTENT-tampered pack carrying the cited id/version → exit 2, never a verdict (the hash guard)", () => {
    // Drop a rule that does NOT fire for the casino-hotel intent, so the decision
    // would STILL be deny — without the hash guard this replays clean and emits a
    // false REPRODUCED (exit 0). Same id/version, different bytes ⇒ different hash.
    const pack = JSON.parse(readFileSync(genuinePackPath, "utf8")) as Pack;
    pack.rules = pack.rules.filter((rule) => rule.id !== "INTOXICANTS-MCC");
    const tamperedPath = join(workDir, "content-tampered.json");
    writeFileSync(tamperedPath, JSON.stringify(pack, null, 2), "utf8");

    const { status, out } = runReplay(tamperedPath);
    expect(status).toBe(2); // operator error, NOT a reproducibility verdict
    expect(out).toContain("INPUT ERROR");
    expect(out).toContain("rule_pack_hash");
    expect(out).not.toContain("RESULT: REPRODUCED");
    expect(out).not.toContain("RESULT: NOT REPRODUCED");
  });

  it("a pack whose id/version does NOT match the envelope → exit 2 (the id/version guard)", () => {
    const pack = JSON.parse(readFileSync(genuinePackPath, "utf8")) as Pack;
    pack.version = "0.2.0";
    const otherVersionPath = join(workDir, "other-version.json");
    writeFileSync(otherVersionPath, JSON.stringify(pack, null, 2), "utf8");

    const { status, out } = runReplay(otherVersionPath);
    expect(status).toBe(2);
    expect(out).toContain("INPUT ERROR");
    expect(out).toContain("supply the");
    expect(out).not.toContain("RESULT:");
  });

  it("a foreign-evaluator pack (D12) → exit 1 'replay could not be attempted', NOT an operator error", () => {
    // A genuine artifact whose cited pack pins a DIFFERENT evaluator version (a
    // historical or future pack). The pack is the CORRECT, hash-matching pack, so
    // this is a reproducibility VERDICT (reproduced:null, "could not be attempted",
    // exit 1), NOT an input error (exit 2). Before the loader opt-out, loadRulePack
    // rejected the pack at load and the CLI mis-classified this as exit 2.
    const foreignPack = {
      ...(JSON.parse(readFileSync(genuinePackPath, "utf8")) as Pack),
      required_evaluator_version: "9.9.9", // valid pattern, != EVALUATOR_VERSION 0.1.0
    };
    const foreignPackPath = join(workDir, "foreign-evaluator-pack.json");
    writeFileSync(foreignPackPath, JSON.stringify(foreignPack, null, 2), "utf8");

    // Reuse the genuine artifact's header/signature (replay never checks
    // authenticity) and swap in a payload citing the foreign pack's hash + evaluator.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const foreignEnvelope = {
      ...envelope,
      evaluator_version: "9.9.9",
      rule_pack_hash: sha256Hex(canonicalize(foreignPack)),
    };
    const foreignPayload = Buffer.from(
      JSON.stringify(foreignEnvelope),
      "utf8",
    ).toString("base64url");
    const foreignEvidencePath = join(workDir, "foreign-evaluator.evidence.jws");
    writeFileSync(foreignEvidencePath, `${header}.${foreignPayload}.${signature}`, "utf8");

    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        foreignEvidencePath,
        "--pack",
        foreignPackPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // a reproducibility verdict, NOT exit 2
    expect(out).toContain("NOT REPRODUCED — replay could not be attempted");
    expect(out).toContain("9.9.9"); // the D12 detail names the pinned evaluator
    expect(out).not.toContain("INPUT ERROR");
  });

  it("a tampered artifact carrying a lone surrogate → clean exit 2, never an uncaught crash", () => {
    // RFC 8785 §3.2.2.2 makes canonicalize() throw on invalid Unicode, and replay
    // canonicalizes reason_codes/matched_rules to compare them — so a malformed
    // envelope must surface as a STRUCTURED operator error, not a stack trace.
    // Bare replay does not authenticate and rule_pack_hash is left matching the
    // genuine pack, so this reaches the reproducibility leg (the crash site).
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    envelope["reason_codes"] = ["MAYSIR", "\uD800"]; // inject a lone surrogate
    const tamperedPayload = Buffer.from(JSON.stringify(envelope), "utf8").toString(
      "base64url",
    );
    const tamperedPath = join(workDir, "lone-surrogate.jws");
    writeFileSync(tamperedPath, `${header}.${tamperedPayload}.${signature}`, "utf8");

    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        tamperedPath,
        "--pack",
        genuinePackPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2); // operator error, NOT a crash or a verdict
    expect(out).toContain("INPUT ERROR");
    expect(out).toContain("invalid Unicode");
    expect(out).not.toContain("CanonicalizationError"); // no raw stack trace leaked
    expect(out).not.toContain("RESULT:");
  });

  it("missing --pack → exit 2 with a usage message (operator error)", () => {
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", evidencePath],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(2);
    expect(result.stdout + result.stderr).toContain("usage:");
  });
});

describe("replay --jwks combined verdict (opt-in authenticity)", () => {
  it("genuine evidence + cited pack + correct --jwks → REPRODUCED and AUTHENTICITY PASS, exit 0", () => {
    const { status, out } = runReplay(genuinePackPath, genuineJwksPath);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain("AUTHENTICITY (--jwks): PASS");
    expect(out).toContain("exit 0 requires BOTH");
    expect(status).toBe(0);
  });

  it("bare replay (no --jwks) loudly labels that authenticity was NOT checked, still exit 0", () => {
    const { status, out } = runReplay(genuinePackPath);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain("authenticity was NOT checked");
    expect(status).toBe(0);
  });

  it("reproduces but --jwks resolves NO key for the kid → AUTHENTICITY FAIL, exit 1 (not a false success)", () => {
    // The decision still re-derives, but the supplied JWKS cannot authenticate the
    // artifact. exit 0 must be withheld: combined mode requires BOTH properties.
    const emptyJwksPath = join(workDir, "empty-jwks.json");
    writeFileSync(emptyJwksPath, JSON.stringify({ keys: [] }), "utf8");

    const { status, out } = runReplay(genuinePackPath, emptyJwksPath);
    expect(out).toContain("RESULT: REPRODUCED");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(status).toBe(1);
  });

  it("a malformed --jwks file is an operator error (exit 2), never an authenticity verdict", () => {
    const badJwksPath = join(workDir, "bad-jwks.json");
    writeFileSync(badJwksPath, "{ not json", "utf8");

    const { status, out } = runReplay(genuinePackPath, badJwksPath);
    expect(status).toBe(2);
    expect(out).toContain("INPUT ERROR");
    expect(out).not.toContain("AUTHENTICITY");
  });
});
