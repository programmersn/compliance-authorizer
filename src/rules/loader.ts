/**
 * Rule-pack loader (ET3): parse → validate (TypeBox + per-operator value
 * constraints) → assert evaluator compatibility (D12) → canonicalize once →
 * hash once. The hash is computed AT LOAD and cached; request handling never
 * re-canonicalizes the pack (perf lock).
 *
 * A pack that fails ANY check refuses to load — a malformed pack is a boot
 * failure, never a runtime "best effort".
 */
import { readFileSync } from "node:fs";
import { Value } from "@sinclair/typebox/value";
import { canonicalize } from "../crypto/canonicalize.ts";
import { sha256Hex } from "../crypto/hash.ts";
import { EVALUATOR_VERSION } from "./evaluator.ts";
import {
  RulePackSchema,
  type Condition,
  type RulePack,
} from "./pack-schema.ts";

export class RulePackError extends Error {
  override name = "RulePackError";
}

export interface LoadedRulePack {
  pack: RulePack;
  /** RFC 8785 canonical form of the pack — the exact hashed text. */
  canonical: string;
  /** Lowercase-hex SHA-256 of the canonical form (the published rule_pack_hash). */
  hash: string;
}

function isJsonPrimitive(value: unknown): boolean {
  const type = typeof value;
  return type === "string" || type === "number" || type === "boolean";
}

function assertConditionValue(condition: Condition, where: string): void {
  const { op, value } = condition;
  switch (op) {
    case "exists":
      if (value !== undefined) {
        throw new RulePackError(`${where}: op "exists" must not carry a value`);
      }
      return;
    case "equals":
    case "includes":
      if (!isJsonPrimitive(value)) {
        throw new RulePackError(
          `${where}: op "${op}" requires a string/number/boolean value`,
        );
      }
      return;
    case "in":
    case "not_in":
      if (
        !Array.isArray(value) ||
        value.length === 0 ||
        !value.every(isJsonPrimitive)
      ) {
        throw new RulePackError(
          `${where}: op "${op}" requires a non-empty array of primitives`,
        );
      }
      return;
    case "gte":
    case "lte":
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new RulePackError(
          `${where}: op "${op}" requires a finite number value`,
        );
      }
      return;
  }
}

/** Parse and fully validate a rule pack from its JSON text. */
export function loadRulePack(jsonText: string): LoadedRulePack {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch (cause) {
    throw new RulePackError("rule pack is not valid JSON", { cause });
  }

  if (!Value.Check(RulePackSchema, parsed)) {
    const first = Value.Errors(RulePackSchema, parsed).First();
    throw new RulePackError(
      `rule pack failed schema validation at ${first?.path ?? "?"}: ${first?.message ?? "unknown error"}`,
    );
  }
  const pack: RulePack = parsed;

  // D12: the scholar signs rule_pack_hash; the pack pins the evaluator semantics
  // it was authored against. Exact match at v0.x — no ranges, no drift.
  if (pack.required_evaluator_version !== EVALUATOR_VERSION) {
    throw new RulePackError(
      `rule pack requires evaluator ${pack.required_evaluator_version}, ` +
        `but this engine is ${EVALUATOR_VERSION} (D12 exact-match contract)`,
    );
  }

  const ruleIds = new Set<string>();
  for (const rule of pack.rules) {
    if (ruleIds.has(rule.id)) {
      throw new RulePackError(`duplicate rule id "${rule.id}"`);
    }
    ruleIds.add(rule.id);
    rule.all_of.forEach((condition, index) =>
      assertConditionValue(condition, `rule ${rule.id} all_of[${index}]`),
    );
  }

  const precedence = pack.conflict_resolution.decision_precedence;
  if (new Set(precedence).size !== 3) {
    throw new RulePackError(
      "conflict_resolution.decision_precedence must contain allow, review and deny exactly once",
    );
  }

  const canonical = canonicalize(pack);
  return { pack, canonical, hash: sha256Hex(canonical) };
}

/** Load a rule pack from disk (pretty-printed JSON file, git-tracked). */
export function loadRulePackFile(path: string): LoadedRulePack {
  return loadRulePack(readFileSync(path, "utf8"));
}
