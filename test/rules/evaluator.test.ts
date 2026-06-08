/**
 * Evaluator + loader tests: exact decisions (deterministic — no fuzzy
 * matching), data-driven conflict precedence, the golden pack hash, and the
 * loader's refusal matrix. Scenario labels are GENERIC by policy
 * (casino-hotel / mixed-revenue ETF / subscription) — never real institutions.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { EVALUATOR_VERSION, evaluate } from "../../src/rules/evaluator.ts";
import {
  RulePackError,
  loadRulePack,
  loadRulePackFile,
} from "../../src/rules/loader.ts";
import type { Condition, RulePack } from "../../src/rules/pack-schema.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const packPath = join(repoRoot, "rule-packs", "shariah", "0.1.0.json");
const loaded = loadRulePackFile(packPath);

/**
 * Golden hash of rule-packs/shariah/0.1.0.json (sha256 over its RFC 8785
 * canonical form). If this assertion fails, the pack CONTENT changed — that is
 * a new pack version + (post-certification) a re-certification event, never a
 * silent edit.
 */
const GOLDEN_PACK_HASH =
  "37b90be117e0e5d2f15c815505761661d36a4ddb84eea9f9c544fec3beddb0eb";

const intent = (overrides: Record<string, unknown> = {}) => ({
  profile: "shariah-v0.1",
  merchant: { name: "synthetic-merchant", mcc: "5411", attributes: [] },
  amount: { value: 120.5, currency: "EUR" },
  ...overrides,
});

describe("golden pack hash + canonicalization invariance (the published hash)", () => {
  it("the loaded pack hash equals the published golden hash", () => {
    expect(loaded.hash).toBe(GOLDEN_PACK_HASH);
    expect(loaded.pack.version).toBe("0.1.0");
    expect(loaded.pack.required_evaluator_version).toBe(EVALUATOR_VERSION);
  });

  it("reformatting the pack file (whitespace/key order) does NOT change the hash", () => {
    const parsed = JSON.parse(readFileSync(packPath, "utf8")) as Record<string, unknown>;
    // Reverse top-level key order and re-indent with 4 spaces.
    const reordered: Record<string, unknown> = {};
    for (const key of Object.keys(parsed).reverse()) reordered[key] = parsed[key];
    const reformatted = loadRulePack(JSON.stringify(reordered, null, 4));
    expect(reformatted.hash).toBe(GOLDEN_PACK_HASH);
  });
});

describe("scenario decisions (exact, deterministic)", () => {
  it("regular hotel booking → allow, no reasons (casino-hotel scenario, permissible half)", () => {
    const result = evaluate(
      intent({ merchant: { name: "seaside-hotel", mcc: "7011", attributes: [] } }),
      loaded.pack,
    );
    expect(result).toEqual({ decision: "allow", reason_codes: [], matched_rules: [] });
  });

  it("casino-hotel booking → deny MAYSIR via merchant attributes", () => {
    const result = evaluate(
      intent({
        merchant: {
          name: "casino-hotel",
          mcc: "7011",
          attributes: ["casino", "gambling"],
        },
      }),
      loaded.pack,
    );
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR"]);
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual(["MAYSIR-ATTR"]);
  });

  it("online-betting merchant → deny MAYSIR via MCC 7995 (subscription scenario, prohibited half)", () => {
    const result = evaluate(
      intent({
        merchant: { name: "online-betting-platform", mcc: "7995", attributes: [] },
        recurring: true,
      }),
      loaded.pack,
    );
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR"]);
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual(["MAYSIR-MCC"]);
  });

  it("streaming subscription → allow (subscription scenario, permissible half)", () => {
    const result = evaluate(
      intent({
        merchant: { name: "streaming-service", mcc: "5815", attributes: [] },
        recurring: true,
      }),
      loaded.pack,
    );
    expect(result.decision).toBe("allow");
  });

  it("mixed-revenue ETF at 12% impermissible share → review MIXED_REVENUE", () => {
    const result = evaluate(
      intent({
        merchant: { name: "mixed-revenue-etf", mcc: "6211", attributes: [] },
        screening: { mixed_revenue_ratio: 0.12 },
      }),
      loaded.pack,
    );
    expect(result.decision).toBe("review");
    expect(result.reason_codes).toEqual(["MIXED_REVENUE"]);
  });

  it("threshold boundary: ratio 0.05 → review; 0.049 → allow (gte semantics)", () => {
    const at = evaluate(
      intent({ screening: { mixed_revenue_ratio: 0.05 } }),
      loaded.pack,
    );
    const below = evaluate(
      intent({ screening: { mixed_revenue_ratio: 0.049 } }),
      loaded.pack,
    );
    expect(at.decision).toBe("review");
    expect(below.decision).toBe("allow");
  });

  it("multi-violation merchant (betting MCC + alcohol attribute) → deny [MAYSIR, INTOXICANTS]", () => {
    const result = evaluate(
      intent({
        merchant: { name: "multi-violation-venue", mcc: "7995", attributes: ["alcohol"] },
      }),
      loaded.pack,
    );
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR", "INTOXICANTS"]);
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual([
      "MAYSIR-MCC",
      "INTOXICANTS-ATTR",
    ]);
  });

  it("unknown MCC falls through to the pack default (allow) — documented limitation", () => {
    const result = evaluate(
      intent({ merchant: { name: "corner-grocery", mcc: "5411", attributes: [] } }),
      loaded.pack,
    );
    expect(result.decision).toBe("allow");
  });
});

describe("conflict precedence is DATA from the pack, not engine code", () => {
  const conflictIntent = intent({
    merchant: {
      name: "derivatives-and-gambling-venue",
      mcc: "6211",
      attributes: ["speculative-derivatives", "gambling"],
    },
  });

  it("deny rule + review rule both match → deny wins under the shipped precedence", () => {
    const result = evaluate(conflictIntent, loaded.pack);
    expect(result.decision).toBe("deny");
    expect(result.reason_codes).toEqual(["MAYSIR", "GHARAR"]);
  });

  it("flipping the pack's decision_precedence flips the outcome (same engine)", () => {
    const flipped: RulePack = structuredClone(loaded.pack);
    flipped.conflict_resolution.decision_precedence = ["review", "deny", "allow"];
    const result = evaluate(conflictIntent, flipped);
    expect(result.decision).toBe("review");
  });
});

describe("closed-grammar semantics (missing fields, strictness)", () => {
  // A pack whose single deny rule carries one condition — so a flipped operator
  // or absent-field behavior can never ship silently. `id` defaults to TEST-OP;
  // callers that assert on matched_rules pass an explicit id.
  const singleRulePack = (condition: Condition, id = "TEST-OP"): RulePack => {
    const pack: RulePack = structuredClone(loaded.pack);
    pack.rules = [
      {
        id,
        reason_code: "MAYSIR",
        decision: "deny",
        title: "test",
        description: "test",
        all_of: [condition],
        standards_ref: { status: "pending", note: "test" },
      },
    ];
    return pack;
  };

  it("conditions on absent fields are false — absence never passes a screen", () => {
    // No screening object at all → the gte rule cannot match.
    const result = evaluate(intent(), loaded.pack);
    expect(result.decision).toBe("allow");
  });

  it("not_in on an absent field is FALSE, not true", () => {
    const miniPack = singleRulePack(
      { field: "merchant.category_label", op: "not_in", value: ["safe"] },
      "TEST-NOT-IN",
    );
    const result = evaluate(intent(), miniPack);
    expect(result.decision).toBe("allow"); // rule did NOT match
  });

  it("not_in is TRUE when a present field's value is NOT in the list (deny fires)", () => {
    const miniPack = singleRulePack(
      { field: "merchant.mcc", op: "not_in", value: ["5411", "5412"] },
      "TEST-NOT-IN-TRUE",
    );
    // mcc "7011" is present and NOT in the list → condition true → rule matches.
    const result = evaluate(
      intent({ merchant: { name: "m", mcc: "7011", attributes: [] } }),
      miniPack,
    );
    expect(result.decision).toBe("deny");
    expect(result.matched_rules.map((rule) => rule.rule_id)).toEqual(["TEST-NOT-IN-TRUE"]);
  });

  it("not_in is FALSE when a present field's value IS in the list (no match)", () => {
    const miniPack = singleRulePack(
      { field: "merchant.mcc", op: "not_in", value: ["5411", "7011"] },
      "TEST-NOT-IN-FALSE",
    );
    // mcc "7011" IS in the list → condition false → rule does NOT match.
    const result = evaluate(
      intent({ merchant: { name: "m", mcc: "7011", attributes: [] } }),
      miniPack,
    );
    expect(result.decision).toBe("allow");
    expect(result.matched_rules).toEqual([]);
  });

  it("no type coercion: a numeric mcc never matches a string rule value", () => {
    const result = evaluate(
      intent({ merchant: { name: "m", mcc: 7995 as unknown as string, attributes: [] } }),
      loaded.pack,
    );
    expect(result.decision).toBe("allow"); // 7995 !== "7995" — strict
  });

  it('inherited prototype members are NOT intent fields: exists on "constructor" / "__proto__" is false', () => {
    // Both names pass the schema's field pattern, and a naive property lookup
    // would resolve them via the prototype chain — diverging from the pinned
    // semantics doc (§2: own data fields only). They must read as ABSENT.
    const miniPack: RulePack = structuredClone(loaded.pack);
    miniPack.rules = [
      {
        id: "TEST-PROTO-1",
        reason_code: "MAYSIR",
        decision: "deny",
        title: "test",
        description: "test",
        all_of: [{ field: "constructor", op: "exists" }],
        standards_ref: { status: "pending", note: "test" },
      },
      {
        id: "TEST-PROTO-2",
        reason_code: "MAYSIR",
        decision: "deny",
        title: "test",
        description: "test",
        all_of: [{ field: "merchant.__proto__", op: "exists" }],
        standards_ref: { status: "pending", note: "test" },
      },
    ];
    const result = evaluate(intent(), miniPack);
    expect(result.decision).toBe("allow"); // neither rule matched
    expect(result.matched_rules).toEqual([]);
  });

  // The remaining §3 operator rows — lte / equals / exists — exercised via
  // single-rule packs (singleRulePack, hoisted above) so a flipped comparison
  // can never ship silently.
  it("lte holds at and below the boundary, not above", () => {
    const pack = singleRulePack({
      field: "screening.mixed_revenue_ratio",
      op: "lte",
      value: 0.05,
    });
    expect(
      evaluate(intent({ screening: { mixed_revenue_ratio: 0.05 } }), pack).decision,
    ).toBe("deny");
    expect(
      evaluate(intent({ screening: { mixed_revenue_ratio: 0.049 } }), pack).decision,
    ).toBe("deny");
    expect(
      evaluate(intent({ screening: { mixed_revenue_ratio: 0.051 } }), pack).decision,
    ).toBe("allow");
  });

  it("equals matches exactly one primitive value, with no near-miss", () => {
    const pack = singleRulePack({ field: "merchant.mcc", op: "equals", value: "7995" });
    expect(
      evaluate(intent({ merchant: { name: "m", mcc: "7995", attributes: [] } }), pack)
        .decision,
    ).toBe("deny");
    expect(
      evaluate(intent({ merchant: { name: "m", mcc: "7996", attributes: [] } }), pack)
        .decision,
    ).toBe("allow");
  });

  it("exists is true for a present field (even a falsy 0) and false when absent", () => {
    const pack = singleRulePack({
      field: "screening.mixed_revenue_ratio",
      op: "exists",
    });
    expect(
      evaluate(intent({ screening: { mixed_revenue_ratio: 0 } }), pack).decision,
    ).toBe("deny");
    expect(evaluate(intent(), pack).decision).toBe("allow");
  });
});

describe("loader refusal matrix (a bad pack never loads)", () => {
  const parsedPack = () =>
    JSON.parse(readFileSync(packPath, "utf8")) as Record<string, unknown>;

  it("rejects a mismatched required_evaluator_version (D12 exact match)", () => {
    const pack = parsedPack();
    pack["required_evaluator_version"] = "0.9.9";
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(RulePackError);
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/D12/);
  });

  it("rejects duplicate rule ids", () => {
    const pack = parsedPack();
    const rules = pack["rules"] as Record<string, unknown>[];
    rules.push({ ...rules[0] });
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/duplicate rule id/);
  });

  it("rejects unknown operators (closed grammar)", () => {
    const pack = parsedPack();
    const rules = pack["rules"] as { all_of: { op: string }[] }[];
    rules[0]!.all_of[0]!.op = "matches_regex";
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(RulePackError);
  });

  it("rejects operator/value type mismatches (gte with a string)", () => {
    const pack = parsedPack();
    const rules = pack["rules"] as { all_of: { op: string; value: unknown }[] }[];
    const gteRule = rules.find((rule) => rule.all_of[0]!.op === "gte");
    gteRule!.all_of[0]!.value = "0.05";
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/finite number/);
  });

  it('rejects "exists" conditions that carry a value', () => {
    const pack = parsedPack();
    const rules = pack["rules"] as { all_of: { op: string; value?: unknown }[] }[];
    rules[0]!.all_of[0] = { op: "exists", value: true, ...{ field: "merchant.mcc" } };
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/must not carry a value/);
  });

  it("rejects a decision_precedence that does not cover all three decisions", () => {
    const pack = parsedPack();
    (pack["conflict_resolution"] as Record<string, unknown>)["decision_precedence"] = [
      "deny",
      "deny",
      "allow",
    ];
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/exactly once/);
  });

  it("rejects unknown top-level fields (additionalProperties: false)", () => {
    const pack = parsedPack();
    pack["llm_fallback"] = true;
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(RulePackError);
  });

  it("wraps a JSON syntax error as a RulePackError that preserves the underlying cause", () => {
    // A malformed pack file is a boot failure — the original parse error must
    // survive on .cause so an operator can see WHERE the JSON broke.
    let caught: unknown;
    try {
      loadRulePack("{ not valid json");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(RulePackError);
    expect((caught as RulePackError).cause).toBeInstanceOf(SyntaxError);
  });

  it('rejects an "in" condition whose value array is empty', () => {
    const pack = parsedPack();
    const rules = pack["rules"] as { all_of: { op: string; value: unknown }[] }[];
    const inRule = rules.find((rule) => rule.all_of[0]!.op === "in");
    inRule!.all_of[0]!.value = [];
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(RulePackError);
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/non-empty array of primitives/);
  });

  it('rejects a "not_in" condition whose value array holds a non-primitive element', () => {
    const pack = parsedPack();
    const rules = pack["rules"] as { all_of: { op: string; value: unknown }[] }[];
    // Repoint an existing rule's first condition to not_in with an object element.
    rules[0]!.all_of[0] = {
      ...{ field: "merchant.mcc" },
      op: "not_in",
      value: ["7995", { nested: "object" }],
    };
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(RulePackError);
    expect(() => loadRulePack(JSON.stringify(pack))).toThrow(/non-empty array of primitives/);
  });
});
