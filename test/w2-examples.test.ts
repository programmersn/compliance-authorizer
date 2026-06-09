/**
 * THE W2 REPRODUCIBILITY GATE: the committed examples/ let an OUTSIDER, from
 * scratch and with ZERO server trust, (1) verify the demo evidence is authentic
 * and (2) reproduce its "deny" decision — and prove it byte-for-byte.
 *
 * This file extends the W1 sign → offline-verify gate (test/w1-fixture.test.ts):
 * W1 proves a FRESHLY signed envelope round-trips; this proves the COMMITTED
 * artifact does, AND that anyone can regenerate it deterministically. Both run
 * the REAL offline verifier (verifier/verify.mjs) as a child process — zero
 * in-process imports of the verifier path — exactly as an outsider would.
 *
 * Four properties, each a distinct guarantee:
 *   (a) the committed evidence VERIFIES offline (authenticity)
 *   (b) the evidence is BYTE-REPRODUCIBLE from the committed demo key + fixed deps
 *   (c) an outsider WITHOUT the private key still reproduces the decision
 *       (public jwks + pack + .jws alone → offline-verify PASS + replay deny)
 *   (d) flipping one byte makes the offline verifier FAIL (tamper-evidence)
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/rules/evaluator.ts";
import {
  buildExampleEvidence,
  casinoHotelIntent,
  EXAMPLE_EVIDENCE_PATH,
  EXAMPLE_JWKS_PATH,
  EXAMPLE_PACK_PATH,
  loadDemoSigningKey,
  loadExamplePack,
} from "../scripts/build-example.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifierPath = join(repoRoot, "verifier", "verify.mjs");
const replayPath = join(repoRoot, "scripts", "replay.ts");

/** Run the REAL offline verifier as a child process — zero server contact. */
function runVerifier(args: string[]): { status: number | null; stdout: string } {
  const result = spawnSync(process.execPath, [verifierPath, ...args], {
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout + result.stderr };
}

/** Run the offline replay CLI as a child process (the documented outsider step). */
function runReplay(args: string[]): { status: number | null; stdout: string } {
  const result = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--no-warnings", replayPath, ...args],
    { encoding: "utf8" },
  );
  return { status: result.status, stdout: result.stdout + result.stderr };
}

let workDir: string;

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "w2-examples-"));
});

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe("W2 reproducibility gate: the committed examples verify + replay from scratch", () => {
  it("(a) the offline verifier PASSES the committed evidence (exit 0, decision deny, UNCERTIFIED)", () => {
    const { status, stdout } = runVerifier([
      "--evidence", EXAMPLE_EVIDENCE_PATH,
      "--jwks", EXAMPLE_JWKS_PATH,
      "--pack", EXAMPLE_PACK_PATH,
    ]);
    expect(stdout).toContain("RESULT: PASS");
    expect(stdout).toContain('decision "deny"');
    // UNCERTIFIED is unavoidable on every rendered surface — including the CLI.
    expect(stdout).toContain("UNCERTIFIED");
    expect(status).toBe(0);
  });

  it("(b) BYTE-REPRODUCIBLE: regenerating from the committed demo key + fixed deps equals the committed .jws exactly", () => {
    // The SAME builder the generator runs (one source of truth, no drift). The
    // demo key is IMPORTED from examples/issuer.demo.jwk.json, never generated —
    // Ed25519 is deterministic, so identical key + identical canonical envelope
    // bytes ⇒ identical signature ⇒ identical artifact, on any machine.
    const regenerated = buildExampleEvidence(
      loadDemoSigningKey(),
      loadExamplePack(),
    );
    const committed = readFileSync(EXAMPLE_EVIDENCE_PATH, "utf8");
    expect(regenerated).toBe(committed);
    // Guard the on-disk byte contract the verifier depends on: a single-line
    // JWS-compact artifact with no trailing newline (so .gitattributes eol=lf
    // normalization cannot alter the committed bytes).
    expect(committed).not.toContain("\n");
    expect(committed.split(".")).toHaveLength(3);
  });

  it("(c) PUBLIC-ONLY PATH: with ONLY the public jwks + pack + .jws (no private key), offline-verify PASSES and replay reproduces deny", () => {
    // (c.1) Authenticity from public material alone — the private key never
    // touches this path. An outsider has exactly these three public files.
    const { status: verifyStatus, stdout: verifyOut } = runVerifier([
      "--evidence", EXAMPLE_EVIDENCE_PATH,
      "--jwks", EXAMPLE_JWKS_PATH,
      "--pack", EXAMPLE_PACK_PATH,
    ]);
    expect(verifyOut).toContain("RESULT: PASS");
    expect(verifyStatus).toBe(0);

    // (c.2) Reproducibility via the documented `npm run replay` step, run as a
    // child process exactly as the outsider workflow in REPRODUCIBILITY.md does.
    const { status: replayStatus, stdout: replayOut } = runReplay([
      "--evidence", EXAMPLE_EVIDENCE_PATH,
      "--pack", EXAMPLE_PACK_PATH,
    ]);
    expect(replayOut).toContain("RESULT: REPRODUCED");
    expect(replayOut).toContain('decision "deny"');
    expect(replayStatus).toBe(0);

    // (c.3) And the in-repo evaluator agrees, decoding the cited payment_intent
    // straight from the committed envelope (not the literal) and re-deriving it.
    const committed = readFileSync(EXAMPLE_EVIDENCE_PATH, "utf8");
    const payloadB64 = committed.split(".")[1] as string;
    const envelope = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const intent = envelope["payment_intent"] as Record<string, unknown>;
    const replayed = evaluate(intent, loadExamplePack().pack);
    expect(replayed.decision).toBe(envelope["decision"]);
    expect(replayed.decision).toBe("deny");
    expect(replayed.reason_codes).toEqual(["MAYSIR"]);
    // The decoded intent is the one the example documents (the generic label).
    expect((intent["merchant"] as Record<string, unknown>)["name"]).toBe(
      "casino-hotel",
    );
  });

  it("(d) TAMPER: flipping one byte in the committed evidence makes the offline verifier FAIL (exit 1)", () => {
    // Mutate a TEMP copy — never the committed artifact. Flip one char inside the
    // signature segment so the structure stays a 3-part JWS but the Ed25519
    // signature no longer verifies.
    const committed = readFileSync(EXAMPLE_EVIDENCE_PATH, "utf8");
    const [header, payloadB64, signature] = committed.split(".") as [
      string,
      string,
      string,
    ];
    const mid = Math.floor(signature.length / 2);
    const flipped = signature[mid] === "A" ? "B" : "A";
    const tampered = `${header}.${payloadB64}.${signature.slice(0, mid)}${flipped}${signature.slice(mid + 1)}`;
    expect(tampered).not.toBe(committed); // a real byte changed

    const tamperedPath = join(workDir, "tampered.evidence.jws");
    writeFileSync(tamperedPath, tampered, "utf8");

    const { status, stdout } = runVerifier([
      "--evidence", tamperedPath,
      "--jwks", EXAMPLE_JWKS_PATH,
      "--pack", EXAMPLE_PACK_PATH,
    ]);
    expect(stdout).toContain("RESULT: FAIL");
    expect(status).toBe(1);
  });
});

describe("W2 example integrity: the demo key is committed and re-derives the published intent", () => {
  it("the casinoHotelIntent the example signs re-derives a deny under the source pack", () => {
    // A direct guard that the frozen literal and the source pack still produce
    // the deny the example claims — independent of the committed .jws bytes.
    const evaluation = evaluate(casinoHotelIntent, loadExamplePack().pack);
    expect(evaluation.decision).toBe("deny");
    expect(evaluation.reason_codes).toEqual(["MAYSIR"]);
  });
});
