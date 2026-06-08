/**
 * TypeBox schema for rule packs — the single source of truth (D10) for what a
 * pack may contain. The predicate grammar is deliberately CLOSED (D4 / T-19
 * DSL-creep guard): a fixed set of operators over dot-path fields, combined
 * only with all_of (AND). Anything richer is a new evaluator version.
 */
import { Type, type Static } from "@sinclair/typebox";

export const DecisionSchema = Type.Union(
  [Type.Literal("allow"), Type.Literal("review"), Type.Literal("deny")],
  { $id: "Decision" },
);
export type Decision = Static<typeof DecisionSchema>;

export const ConditionOpSchema = Type.Union([
  Type.Literal("equals"),
  Type.Literal("in"),
  Type.Literal("not_in"),
  Type.Literal("gte"),
  Type.Literal("lte"),
  Type.Literal("includes"),
  Type.Literal("exists"),
]);
export type ConditionOp = Static<typeof ConditionOpSchema>;

export const ConditionSchema = Type.Object(
  {
    field: Type.String({
      minLength: 1,
      // dot path of snake_case segments into the payment intent
      pattern: "^[a-z0-9_]+(\\.[a-z0-9_]+)*$",
    }),
    op: ConditionOpSchema,
    value: Type.Optional(Type.Unknown()),
  },
  { additionalProperties: false },
);
export type Condition = Static<typeof ConditionSchema>;

export const StandardsRefSchema = Type.Object(
  {
    status: Type.Literal("pending"),
    note: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);

export const RuleSchema = Type.Object(
  {
    id: Type.String({ pattern: "^[A-Z0-9][A-Z0-9_-]*$" }),
    reason_code: Type.String({ pattern: "^[A-Z][A-Z0-9_]*$" }),
    decision: Type.Union([Type.Literal("deny"), Type.Literal("review")]),
    title: Type.String({ minLength: 1 }),
    description: Type.String({ minLength: 1 }),
    all_of: Type.Array(ConditionSchema, { minItems: 1 }),
    standards_ref: StandardsRefSchema,
  },
  { additionalProperties: false },
);
export type Rule = Static<typeof RuleSchema>;

export const RulePackSchema = Type.Object(
  {
    id: Type.String({ pattern: "^[a-z0-9][a-z0-9-]*$" }),
    version: Type.String({ pattern: "^\\d+\\.\\d+\\.\\d+$" }),
    profile: Type.String({ minLength: 1 }),
    status: Type.Literal("uncertified"),
    title: Type.String({ minLength: 1 }),
    description: Type.String({ minLength: 1 }),
    required_evaluator_version: Type.String({ pattern: "^\\d+\\.\\d+\\.\\d+$" }),
    default_decision: DecisionSchema,
    conflict_resolution: Type.Object(
      {
        strategy: Type.Literal("most_restrictive"),
        // Data, not code: the evaluator READS precedence from here, so changing
        // the pack changes the outcome (eng test-plan conflict edge case).
        decision_precedence: Type.Array(DecisionSchema, {
          minItems: 3,
          maxItems: 3,
        }),
      },
      { additionalProperties: false },
    ),
    rules: Type.Array(RuleSchema, { minItems: 1 }),
  },
  { additionalProperties: false },
);
export type RulePack = Static<typeof RulePackSchema>;
