/**
 * Deterministic rule evaluator — NO LLM, no clock, no randomness, no I/O.
 * Same intent + same pack → same decision, always (CXT-B replayability).
 *
 * The full semantics contract (operators, missing fields, normalization,
 * precedence) is pinned in docs/evaluator-semantics.md and versioned by
 * EVALUATOR_VERSION. Rule packs declare required_evaluator_version (D12), so a
 * semantics change here is a certification-invalidating event by construction.
 */
import type { Condition, Decision, Rule, RulePack } from "./pack-schema.ts";

/**
 * Bumped on ANY observable semantics change. Packs pin this exactly; the
 * loader refuses a pack whose required_evaluator_version differs (D12).
 */
export const EVALUATOR_VERSION = "0.1.0";

export interface MatchedRule {
  rule_id: string;
  reason_code: string;
  decision: "deny" | "review";
  title: string;
  description: string;
  standards_ref: Rule["standards_ref"];
}

export interface Evaluation {
  decision: Decision;
  reason_codes: string[];
  matched_rules: MatchedRule[];
}

type JsonPrimitive = string | number | boolean;

function isPrimitive(value: unknown): value is JsonPrimitive {
  const type = typeof value;
  return type === "string" || type === "number" || type === "boolean";
}

/**
 * Resolve a dot path against the intent. Traverses plain objects only; any
 * missing or non-object segment yields undefined (the condition then fails).
 */
function resolvePath(intent: Record<string, unknown>, path: string): unknown {
  let current: unknown = intent;
  for (const segment of path.split(".")) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current)
    ) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

/**
 * Closed predicate semantics (docs/evaluator-semantics.md §3):
 * every operator except `exists` evaluates to FALSE when the field is absent.
 * Comparisons are strict — no type coercion, no case folding.
 */
function conditionHolds(
  condition: Condition,
  intent: Record<string, unknown>,
): boolean {
  const resolved = resolvePath(intent, condition.field);
  switch (condition.op) {
    case "exists":
      return resolved !== undefined;
    case "equals":
      return isPrimitive(resolved) && resolved === condition.value;
    case "in":
      return (
        isPrimitive(resolved) &&
        Array.isArray(condition.value) &&
        condition.value.includes(resolved)
      );
    case "not_in":
      return (
        isPrimitive(resolved) &&
        Array.isArray(condition.value) &&
        !condition.value.includes(resolved)
      );
    case "gte":
      return (
        typeof resolved === "number" &&
        typeof condition.value === "number" &&
        resolved >= condition.value
      );
    case "lte":
      return (
        typeof resolved === "number" &&
        typeof condition.value === "number" &&
        resolved <= condition.value
      );
    case "includes":
      return (
        Array.isArray(resolved) &&
        isPrimitive(condition.value) &&
        resolved.includes(condition.value)
      );
  }
}

/** Evaluate a payment intent against a rule pack. Pure and deterministic. */
export function evaluate(
  intent: Record<string, unknown>,
  pack: RulePack,
): Evaluation {
  const matched = pack.rules.filter((rule) =>
    rule.all_of.every((condition) => conditionHolds(condition, intent)),
  );

  const matched_rules: MatchedRule[] = matched.map((rule) => ({
    rule_id: rule.id,
    reason_code: rule.reason_code,
    decision: rule.decision,
    title: rule.title,
    description: rule.description,
    standards_ref: rule.standards_ref,
  }));

  // Reason codes: unique, in pack order (deterministic, documented).
  const reason_codes = [...new Set(matched.map((rule) => rule.reason_code))];

  if (matched.length === 0) {
    return { decision: pack.default_decision, reason_codes, matched_rules };
  }

  // Precedence is DATA read from the pack, not code: the first decision in
  // decision_precedence that any matched rule carries wins.
  const matchedDecisions = new Set(matched.map((rule) => rule.decision));
  for (const decision of pack.conflict_resolution.decision_precedence) {
    if (matchedDecisions.has(decision as "deny" | "review")) {
      return { decision, reason_codes, matched_rules };
    }
  }
  // Unreachable when the loader has validated decision_precedence covers all
  // three decisions; kept as a hard failure rather than a silent default.
  throw new Error(
    "rule pack decision_precedence does not cover the matched decisions",
  );
}
