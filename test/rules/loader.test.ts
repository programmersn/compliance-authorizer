/**
 * loadRulePack: the D12 evaluator-version assertion is OPT-OUT.
 *
 * The SERVER must only load packs it can run, so the default fails closed on a
 * `required_evaluator_version` mismatch (D12 exact-match). The offline replay CLI
 * opts out so a genuine foreign-evaluator pack is validated + hashed and handed
 * to replayEnvelope (a `reproduced:null` verdict), instead of being pre-empted as
 * an operator/input error. Only the version assertion is relaxed: schema
 * validation and the content hash are unchanged.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/crypto/canonicalize.ts";
import { sha256Hex } from "../../src/crypto/hash.ts";
import { loadRulePack, RulePackError } from "../../src/rules/loader.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const genuinePackText = readFileSync(join(repoRoot, "examples", "pack.json"), "utf8");
const foreignPack = (): Record<string, unknown> => ({
  ...(JSON.parse(genuinePackText) as Record<string, unknown>),
  required_evaluator_version: "9.9.9", // valid version pattern, != EVALUATOR_VERSION 0.2.0
});

describe("loadRulePack — D12 evaluator-version enforcement is opt-out", () => {
  it("rejects a foreign-evaluator pack BY DEFAULT (D12 exact-match, the server's fail-closed posture)", () => {
    expect(() => loadRulePack(JSON.stringify(foreignPack()))).toThrow(/D12 exact-match contract/);
  });

  it("loads and hashes a foreign-evaluator pack when enforceEvaluatorVersion:false (the replay CLI's posture)", () => {
    const foreign = foreignPack();
    const loaded = loadRulePack(JSON.stringify(foreign), { enforceEvaluatorVersion: false });
    expect(loaded.pack.required_evaluator_version).toBe("9.9.9");
    // The content binding is untouched: the hash is still sha256 of the canonical pack,
    // so the replay CLI's rule_pack_hash guard still rejects a wrong or tampered pack.
    expect(loaded.hash).toBe(sha256Hex(canonicalize(foreign)));
  });

  it("still rejects a schema-invalid pack even with enforceEvaluatorVersion:false (only the version check is relaxed)", () => {
    const broken = { ...foreignPack(), rules: "not-an-array" };
    expect(() => loadRulePack(JSON.stringify(broken), { enforceEvaluatorVersion: false })).toThrow(
      RulePackError,
    );
  });
});
