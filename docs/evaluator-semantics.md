# Evaluator semantics — version 0.1.0

This document pins the observable semantics of the rule evaluator
(`src/rules/evaluator.ts`). It exists so that a decision can be **replayed**:
given `rule_pack_hash` + `evaluator_version` + `intent_hash`, a third party can
re-derive the exact same decision (CXT-B).

**Versioning contract (D12).** `EVALUATOR_VERSION` is bumped on ANY observable
semantics change, however small. Every rule pack declares
`required_evaluator_version`, and the loader refuses a pack whose declared
version does not **exactly match** the engine (no ranges at v0.x). Because the
scholar's certification signature covers `rule_pack_hash`, and the pack's hash
covers `required_evaluator_version`, a semantics change here is a
certification-invalidating event by construction: it forces a new pack version
and a re-certification.

## 1. Inputs

- **Payment intent** — a JSON object (validated at the API boundary by the
  TypeBox schema; the evaluator itself accepts any JSON object).
- **Rule pack** — a JSON document validated by `src/rules/pack-schema.ts` and
  the loader's per-operator checks. The pack's canonical form is its RFC 8785
  (JCS) serialization; `rule_pack_hash` is the lowercase-hex SHA-256 of that
  canonical text.

## 2. Field resolution

Rule conditions address intent fields by **dot path** (e.g. `merchant.mcc`,
`screening.mixed_revenue_ratio`):

- Path segments traverse **plain JSON objects only**. If any segment is
  missing, or an intermediate value is `null`, an array, or a primitive, the
  resolved value is *absent*.
- Only a member **present in the JSON data itself** resolves. Names a host
  language may expose on every object (JavaScript `constructor`, `__proto__`,
  …) are *absent* unless the intent document literally carries them.
- Arrays are never indexed by path at evaluator 0.1.0 (use the `includes`
  operator on an array-valued field instead).

## 3. Operators (closed set)

The grammar is **closed** (T-19 DSL-creep guard): exactly these operators,
combined only by `all_of` (logical AND) within a rule. There is no `any_of`,
no negation combinator, and no nesting at evaluator 0.1.0. OR across
alternatives is expressed as separate rules sharing a `reason_code`.

| op | value type | holds iff |
|---|---|---|
| `equals` | string \| number \| boolean | field is present, primitive, and strictly equal (`===`) to value |
| `in` | non-empty array of primitives | field is present, primitive, and strictly equal to one element |
| `not_in` | non-empty array of primitives | field is present, primitive, and equal to **no** element |
| `gte` | finite number | field is present, a number, and `field >= value` |
| `lte` | finite number | field is present, a number, and `field <= value` |
| `includes` | string \| number \| boolean | field is present, an **array**, and strictly contains value |
| `exists` | — (must be omitted) | field is present (not `undefined`) |

**Missing-field rule:** every operator except `exists` evaluates to **false**
when the field is absent. In particular, `not_in` on an absent field is
*false*, not true — absence is never read as "passes a screen".

## 4. Normalization

There is **none**. Comparisons are strict and case-sensitive; no type coercion,
no trimming, no case folding, no unicode normalization. Conventions used by the
packs (not enforced by the evaluator):

- `merchant.mcc` is a **4-digit string** (e.g. `"7995"`), never a number, so
  leading zeros survive (`"0742"`).
- `merchant.attributes` entries are lowercase kebab-case tokens
  (e.g. `"casino"`, `"interest-bearing-credit"`).

## 5. Decision combination

1. A rule **matches** when *all* of its `all_of` conditions hold.
2. If **no** rule matches, the decision is the pack's `default_decision` and
   `reason_codes` / `matched_rules` are empty. An MCC that appears in no rule
   therefore falls through to the default — for the Shariah v0.1 demo pack that
   is `allow`, an honestly-documented limitation of category-level screening.
3. If one or more rules match, the decision is resolved from the pack's
   `conflict_resolution.decision_precedence` — the first decision in that array
   carried by any matched rule wins. Precedence is **data read from the pack**,
   not engine code: change the pack's precedence array and the outcome changes
   (and so does `rule_pack_hash`).
4. `reason_codes` are the matched rules' codes, **de-duplicated, in pack
   order**. `matched_rules` lists every matched rule, in pack order.

## 6. Determinism

The evaluator is a pure function: no clock, no randomness, no I/O, no LLM.
`evaluate(intent, pack)` is referentially transparent, which is what makes the
evidence envelope's `(rule_pack_hash, evaluator_version, intent_hash)` triple a
complete replay key. Envelope-level fields that legitimately vary per call
(`decision_id`, `decision_timestamp`) are injected OUTSIDE the evaluator and
are never inputs to the decision.
