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
      required_evaluator_version: "9.9.9", // valid pattern, != EVALUATOR_VERSION 0.2.0
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

  it("an unknown flag → exit 2 (operator error), never exit 1 — parseArgs throws but bad usage is not a verdict", () => {
    // parseArgs (strict) throws on an unknown flag; the throw is routed to exit 2,
    // never an uncaught Node exit 1 (the verdict code) that automation would misread
    // as "not reproduced / not authentic" for a mere typo.
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", evidencePath, "--pack", genuinePackPath, "--bogus-flag"],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(2);
    expect(result.stdout + result.stderr).toContain("INPUT ERROR");
    expect(result.stdout + result.stderr).not.toContain("RESULT:");
  });

  it("evidence that is not a 3-segment JWS → exit 2 INPUT ERROR (structural operator error)", () => {
    const bad = join(workDir, "not-a-jws.txt");
    writeFileSync(bad, "onlyonesegment", "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", bad, "--pack", genuinePackPath],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(2);
    expect(result.stdout + result.stderr).toContain("3-segment");
    expect(result.stdout + result.stderr).not.toContain("RESULT:");
  });

  it("a non-canonical base64url segment (padded payload) → exit 2, never read as reproduced", () => {
    // Node's base64url decoder is lenient (it ignores `=` padding), so a padded
    // payload decodes to the same envelope and bare replay would otherwise emit a
    // REPRODUCED verdict for a non-compact JWS. The canonical-base64url guard (shared
    // with verify.mjs via isCanonicalB64url) rejects it as malformed input instead.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const paddedPath = join(workDir, "padded-payload.jws");
    writeFileSync(paddedPath, `${header}.${payloadB64}=.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", paddedPath, "--pack", genuinePackPath],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2);
    expect(out).toContain("canonical base64url");
    expect(out).not.toContain("RESULT: REPRODUCED");
  });

  it("a malformed envelope MISSING a required field → exit 2 (strict-shape guard), never an exit-1 crash", () => {
    // The strict v0.1 envelope-shape guard (reused from verify.mjs). Without it, a
    // missing reason_codes reached replayEnvelope, whose canonicalize(undefined)
    // threw → a raw CanonicalizationError stack and Node exit 1 (the verdict code).
    // The pack refs are left matching, so this would otherwise reach the replay leg.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<string, unknown>;
    delete envelope["reason_codes"];
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const malformedPath = join(workDir, "missing-reason-codes.jws");
    writeFileSync(malformedPath, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", malformedPath, "--pack", genuinePackPath],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2); // operator error, NOT an exit-1 crash
    expect(out).toContain("v0.1 schema");
    expect(out).toContain("missing fields");
    expect(out).not.toContain("CanonicalizationError"); // no raw stack trace leaked
    expect(out).not.toContain("RESULT:");
  });

  it("a malformed envelope (missing envelope_version) → exit 2, NOT a false REPRODUCED (exit 0)", () => {
    // Bare replay previously had NO schema gate, so deleting envelope_version still
    // printed RESULT: REPRODUCED and exited 0 — an invalid evidence envelope looked
    // reproducible to exit-code-only automation. The strict-shape guard closes that.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<string, unknown>;
    delete envelope["envelope_version"];
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const malformedPath = join(workDir, "missing-envelope-version.jws");
    writeFileSync(malformedPath, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", malformedPath, "--pack", genuinePackPath],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2);
    expect(out).toContain("v0.1 schema");
    expect(out).not.toContain("RESULT: REPRODUCED"); // never a false success
  });

  it("a genuine pack but the envelope's decision was overwritten → RESULT: NOT REPRODUCED, exit 1 (the central verdict)", () => {
    // The tool's reason for existing: the cited decision does not re-derive. Overwrite
    // decision to "allow" while leaving reason_codes/matched_rules at the deny values
    // (bare replay never checks the signature). Re-evaluation still yields deny → a
    // reproducibility VERDICT (exit 1), distinct from the D12 "could not be attempted".
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<string, unknown>;
    envelope["decision"] = "allow"; // re-evaluation will still yield deny
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const mismatchPath = join(workDir, "decision-mismatch.jws");
    writeFileSync(mismatchPath, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", mismatchPath, "--pack", genuinePackPath],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // a verdict, not an operator error
    expect(out).toContain("RESULT: NOT REPRODUCED");
    expect(out).toContain("re-evaluation yields");
    expect(out).not.toContain("could not be attempted"); // not the D12 path
  });

  it("a lone surrogate on a D12 (foreign-evaluator) artifact → exit 2 (malformed wins), never the D12 'could not be attempted'", () => {
    // The CHANGELOG claims uniform rejection "including the D12 evaluator-mismatch
    // path." replayEnvelope's D12 early-return precedes its field canonicalization,
    // so only the up-front canonicalize guard catches a surrogate on a D12 artifact.
    // Pin it: a foreign-evaluator artifact carrying a surrogate is exit 2 (invalid
    // Unicode), NOT the D12 verdict — proof the malformed guard beats the early-return.
    const foreignPack = {
      ...(JSON.parse(readFileSync(genuinePackPath, "utf8")) as Pack),
      required_evaluator_version: "9.9.9",
    };
    const foreignPackPath = join(workDir, "d12-surrogate-pack.json");
    writeFileSync(foreignPackPath, JSON.stringify(foreignPack, null, 2), "utf8");
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<string, unknown>;
    envelope["evaluator_version"] = "9.9.9";
    envelope["rule_pack_hash"] = sha256Hex(canonicalize(foreignPack));
    envelope["reason_codes"] = ["MAYSIR", "\uD800"]; // lone surrogate
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const p = join(workDir, "d12-lone-surrogate.jws");
    writeFileSync(p, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", replayScript, "--evidence", p, "--pack", foreignPackPath],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2);
    expect(out).toContain("invalid Unicode");
    expect(out).not.toContain("could not be attempted");
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

  it("FORGED rule_pack_hash + --jwks → AUTHENTICITY FAIL, exit 1 — NOT an exit-2 'supply the cited pack'", () => {
    // The exit-code-precedence fix: the cited rule_pack_hash is UNAUTHENTICATED at
    // the pack-mismatch check, so a tampered rule_pack_hash (which breaks the
    // signature; the attacker has no key to re-sign) would otherwise trip the
    // exit-2 "supply the exact cited pack" path BEFORE authenticity ran — misreporting
    // forged evidence as an operator/input condition. In --jwks mode the signature
    // must decide: this is an authenticity FAIL (exit 1), and the operator is NOT
    // sent hunting for a "cited pack" that never existed. The genuine pack/jwks are
    // supplied, so the ONLY defect is the forged field.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    envelope["rule_pack_hash"] = "0".repeat(64); // well-formed sha256-hex, but forged
    const forgedPayload = Buffer.from(JSON.stringify(envelope), "utf8").toString(
      "base64url",
    );
    const forgedPath = join(workDir, "forged-pack-hash.jws");
    writeFileSync(forgedPath, `${header}.${forgedPayload}.${signature}`, "utf8");

    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        forgedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // an authenticity VERDICT, not an operator error
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("supply the exact cited pack"); // not misreported as exit-2
    expect(result.status).not.toBe(2);
  });

  it("AUTHENTIC artifact + a content-modified --pack + --jwks → exit 2 (genuine wrong pack), NOT an authenticity fail", () => {
    // The other side of the disambiguation: the artifact is genuine, so the cited
    // rule_pack_hash is signed/real and the operator simply handed the wrong pack.
    // Authenticity passes (no-pack), so this correctly FALLS THROUGH to the exit-2
    // operator error — it must NOT be misreported as an authenticity FAIL.
    const pack = JSON.parse(readFileSync(genuinePackPath, "utf8")) as Pack;
    pack.rules = pack.rules.filter((rule) => rule.id !== "INTOXICANTS-MCC"); // same id/version, different hash
    const modifiedPackPath = join(workDir, "content-modified-for-jwks.json");
    writeFileSync(modifiedPackPath, JSON.stringify(pack, null, 2), "utf8");

    const { status, out } = runReplay(modifiedPackPath, genuineJwksPath);
    expect(status).toBe(2); // operator error: wrong pack for an AUTHENTIC artifact
    expect(out).toContain("INPUT ERROR");
    expect(out).toContain("rule_pack_hash");
    expect(out).not.toContain("AUTHENTICITY (--jwks): FAIL");
  });

  it("a lone surrogate in payment_intent (a field replay does not itself canonicalize) → exit 2, not a silent verdict", () => {
    // The up-front malformed-artifact guard canonicalizes the WHOLE envelope, so a
    // lone surrogate ANYWHERE (here in payment_intent, which replayEnvelope reads but
    // never canonicalizes, and which the D12 early-return would also skip) is a clean
    // operator error — closing the gap where such an artifact previously slipped
    // through bare replay and emitted a RESULT verdict.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const intent = envelope["payment_intent"] as Record<string, unknown>;
    const merchant = intent["merchant"] as Record<string, unknown>;
    merchant["name"] = `casino${String.fromCharCode(0xd800)}hotel`; // lone surrogate
    const malformedPayload = Buffer.from(JSON.stringify(envelope), "utf8").toString(
      "base64url",
    );
    const malformedPath = join(workDir, "intent-lone-surrogate.jws");
    writeFileSync(malformedPath, `${header}.${malformedPayload}.${signature}`, "utf8");

    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        malformedPath,
        "--pack",
        genuinePackPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(2); // malformed artifact = operator error, uniformly
    expect(out).toContain("INPUT ERROR");
    expect(out).toContain("invalid Unicode");
    expect(out).not.toContain("RESULT:"); // never a silent reproducibility verdict
  });

  it("a lone surrogate + --jwks → AUTHENTICITY FAIL (exit 1), never a soft exit-2 operator error", () => {
    // CONTRACT pin (Codex P2, PR #6): in combined mode the VERIFIER's verdict
    // wins on a malformed artifact. verify.mjs classifies these same bytes as
    // FAIL (exit 1) — signature first, then canonical form — so replay --jwks
    // must agree, or the two tools would emit opposite exit codes for one
    // artifact. An exit-2 "operator error" reading would let a forger silence
    // exit-code automation that pages on exit 1 by simply malforming the
    // payload. Bare-mode behavior (exit 2) is pinned separately above — the
    // documented two-tools boundary.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    envelope["reason_codes"] = ["MAYSIR", "\uD800"]; // lone surrogate
    const malformedPayload = Buffer.from(JSON.stringify(envelope), "utf8").toString(
      "base64url",
    );
    const malformedPath = join(workDir, "lone-surrogate-jwks.jws");
    writeFileSync(malformedPath, `${header}.${malformedPayload}.${signature}`, "utf8");

    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        malformedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // the verifier's verdict — not an operator error
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("invalid Unicode");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR"); // exit 2 wording must not appear
    expect(out).not.toContain("RESULT:"); // replay itself still never ran
  });

  it("a malformed envelope MISSING a required field + --jwks → AUTHENTICITY FAIL (exit 1), not an exit-2 shape error", () => {
    // CONTRACT pin (Codex P2, PR #6): the strict-shape guard is mode-aware. With
    // --jwks the artifact gets the verifier's not-valid-evidence verdict (exit 1,
    // here via the broken signature — tampering removed a signed field); only bare
    // replay reads a malformed envelope as an exit-2 operator error.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    delete envelope["reason_codes"];
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const malformedPath = join(workDir, "missing-field-jwks.jws");
    writeFileSync(malformedPath, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        malformedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1);
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("v0.1 schema");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR");
  });

  it("FORGED non-hex rule_pack_hash + --jwks → AUTHENTICITY FAIL (exit 1), NOT an exit-2 'malformed artifact'", () => {
    // The exact Codex-P2 bypass case: tampering rule_pack_hash into a non-hex
    // string makes the envelope BOTH malformed (fails the v0.1 schema's
    // sha256-hex format) and inauthentic (the bytes no longer match the
    // signature). An exit-2 "malformed" reading would swallow the forgery
    // signal AND skip the pack-mismatch disambiguation that exists precisely
    // to name rule_pack_* tampering an authenticity FAIL. The signature is
    // what tells forgery from operator error, so --jwks consults it first.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    envelope["rule_pack_hash"] = "not-a-sha256-hex-string"; // forged AND malformed
    const payload = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const forgedPath = join(workDir, "non-hex-pack-hash-jwks.jws");
    writeFileSync(forgedPath, `${header}.${payload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        forgedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // forgery signal, not operator error
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR");
    expect(out).not.toContain("supply the cited pack"); // disambiguation not bypassed into exit 2
  });

  it("a padded (non-canonical base64url) segment + --jwks → AUTHENTICITY FAIL (exit 1), not exit 2", () => {
    // Codex P2 follow-up: the JWS-segment guards are upstream of the shape gate
    // and must obey the same combined-mode contract. Appending `=` to a segment
    // is the cheapest possible malleation — Node's lenient decoder still reads
    // the same bytes — and verify.mjs rejects it as a structure FAIL (exit 1),
    // so replay --jwks must not soften it to an exit-2 operator error.
    const [header, payloadB64, signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const paddedPath = join(workDir, "padded-payload-jwks.jws");
    writeFileSync(paddedPath, `${header}.${payloadB64}=.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        paddedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1); // the verifier's structure FAIL, not an operator error
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("canonical base64url");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR");
  });

  it("a truncated (2-segment) artifact + --jwks → AUTHENTICITY FAIL (exit 1), not exit 2", () => {
    // Same contract, structure guard: verify.mjs classifies a non-3-segment
    // string as a structure FAIL (exit 1), so the combined verdict must agree.
    const [header, payloadB64] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const truncatedPath = join(workDir, "truncated-jwks.jws");
    writeFileSync(truncatedPath, `${header}.${payloadB64}`, "utf8");
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        truncatedPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1);
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("3-segment");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR");
  });

  it("a non-object JSON payload + --jwks → AUTHENTICITY FAIL (exit 1), not exit 2", () => {
    // Same contract, payload guard: a payload tampered into a JSON array still
    // breaks the signature, and verify.mjs renders a FAIL verdict on those
    // bytes — replay --jwks must not call the forgery an operator error.
    const [header, , signature] = readFileSync(evidencePath, "utf8")
      .trim()
      .split(".") as [string, string, string];
    const arrayPayload = Buffer.from("[]", "utf8").toString("base64url");
    const nonObjectPath = join(workDir, "non-object-payload-jwks.jws");
    writeFileSync(nonObjectPath, `${header}.${arrayPayload}.${signature}`, "utf8");
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--no-warnings",
        replayScript,
        "--evidence",
        nonObjectPath,
        "--pack",
        genuinePackPath,
        "--jwks",
        genuineJwksPath,
      ],
      { encoding: "utf8" },
    );
    const out = result.stdout + result.stderr;
    expect(result.status).toBe(1);
    expect(out).toContain("MALFORMED ARTIFACT");
    expect(out).toContain("JSON object envelope");
    expect(out).toContain("AUTHENTICITY (--jwks): FAIL");
    expect(out).not.toContain("INPUT ERROR");
  });
});
