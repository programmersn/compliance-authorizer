# Evaluator semantics — version 0.2.0

This document pins the observable semantics of the engine's **decision
function**: the rule evaluator (`src/rules/evaluator.ts`) plus, since 0.2.0,
the agent-credential scope layer (`src/vc/enforce.ts`, §7). It exists so that a
decision can be **replayed**: given `rule_pack_hash` + `evaluator_version` +
`intent_hash`, a third party can re-derive the exact same decision (CXT-B).

**Versioning contract (D12).** `EVALUATOR_VERSION` is bumped on ANY observable
semantics change, however small. Every rule pack declares
`required_evaluator_version`, and the loader refuses a pack whose declared
version does not **exactly match** the engine (no ranges at v0.x). Because the
scholar's certification signature covers `rule_pack_hash`, and the pack's hash
covers `required_evaluator_version`, a semantics change here is a
certification-invalidating event by construction: it forces a new pack version
and a re-certification.

**Version history.**

| version | change |
|---|---|
| 0.1.0 | initial closed grammar (§2–§5) |
| 0.2.0 | adds the agent-credential scope layer (§7). Credential-free intents are decided **exactly** as 0.1.0; the bump exists because a credentialed envelope replayed under 0.1.0 semantics would re-derive a different decision. Per D12 this re-versioned the shipped pack (`shariah` 0.1.0 → 0.1.1, rules unchanged, pinning evaluator 0.2.0). |

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

## 5. Decision combination (within the rule pack)

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

The decision function is pure: no clock, no randomness, no I/O, no LLM.
`decideIntent(intent, pack)` (and the `evaluate(intent, pack)` it wraps) is
referentially transparent, which is what makes the evidence envelope's
`(rule_pack_hash, evaluator_version, intent_hash)` triple a complete replay
key. Ed25519 verification inside the credential admission gate (§7) is itself
deterministic, so the property survives the scope layer. Envelope-level fields
that legitimately vary per call (`decision_id`, `decision_timestamp`) are
injected OUTSIDE the evaluator and are never inputs to the decision.

## 7. Agent-credential scope layer (evaluator 0.2.0, ET16/D6/CXT-C)

A payment intent MAY carry an OPTIONAL `agent_credential` field: a synthetic
signed credential presented by (or for) the transacting agent. Because the
credential travels **inside** `payment_intent`, `intent_hash` covers it
automatically — no new envelope field exists for it.

### 7.1 Credential format (closed, minimal — deliberately NOT a W3C VC)

A JWS-compact string over **Ed25519**:

- protected header: exactly `{"alg":"EdDSA","kid":"<did:key DID>"}` — no other
  parameters (no `crit`, no `typ`). `alg` is pinned before key material is
  touched; the issuer key is the **did:key itself** (multicodec `ed25519-pub`),
  which is **self-certifying**: verification needs no key distribution and
  works fully offline.
- payload: the **RFC 8785 canonical bytes** of exactly
  `{"credential_type":"synthetic-agent-mcc-scope/0.1","issuer":"<did:key>",
  "agent_id":"<non-empty string>","scope":{"allowed_mcc":["dddd", …]}}` —
  exact key sets at both levels, `issuer` MUST equal the header `kid`, and
  `allowed_mcc` is a non-empty array of 4-digit MCC strings.
- **NO revocation, NO status, NO expiry** — explicitly locked out of v0.1
  scope, which is also why no clock enters the decision path.

### 7.2 Admission gate (error ≠ deny)

A malformed, tampered, alg-confused, or otherwise **INVALID** credential is an
**integration failure, never a decision**: `POST /authorize` answers 4xx RFC
9457 problem+json (`…/problems/invalid-agent-credential`, no envelope is
signed). The admission verdict is part of the deterministic contract — the same
credential bytes always pass or always fail.

### 7.3 Scope decision and two-layer combination

For an intent carrying a **valid** credential:

1. **Scope layer** — `allow` iff the intent's `merchant.mcc` (resolved per §2:
   own properties of plain objects only) is **strictly equal** to an element of
   `scope.allowed_mcc`; otherwise `deny` carrying the engine-level reason code
   `AGENT_SCOPE_EXCEEDED`. An absent or non-string `merchant.mcc` never passes
   the screen (the §3 missing-field rule).
2. **Combination** — `most_restrictive(pack decision, scope decision)` under
   the **fixed engine severity `deny > review > allow`**. This cross-layer
   severity is ENGINE semantics versioned by `EVALUATOR_VERSION`; the pack's
   `decision_precedence` remains pack DATA and governs **intra-pack** rule
   conflicts only (§5.3). Since the scope layer is binary:

   | pack \ scope | scope allow | scope deny |
   |---|---|---|
   | allow | allow | **deny** |
   | review | review | **deny** |
   | deny | deny | deny |

3. **reason_codes** — the pack's codes (§5.4), then `AGENT_SCOPE_EXCEEDED`
   appended iff the scope layer denied (de-duplicated: not appended twice if a
   pack rule already carried that string). **matched_rules** stays the pack's
   matches only — the scope layer is not a pack rule; its basis is the
   credential embedded in `payment_intent`.

A scope-exceeded outcome is a **SIGNED deny** (HTTP 200 + envelope): a valid
credential whose scope excludes the MCC is a decision, not an error.

### 7.4 Replay re-verifies the credential signature (the explicit choice)

Decision replay (`src/evidence/replay.ts`, shared verbatim by `POST /verify`
and the offline `scripts/replay.ts` CLI) runs the **same** `decideIntent`
function — including a full **offline re-verification of the credential's
Ed25519 signature**. did:key makes this possible with zero inputs beyond the
envelope itself, so signature validity is NOT treated as an
admission-time-only fact whose extracted scope is trusted on replay: the
replayer re-derives the admission verdict from the bytes.

Consequently, an envelope whose cited `payment_intent` embeds an **invalid**
credential — only producible by tampering-then-re-signing or a buggy signer —
is a **conclusive NOT REPRODUCED** (`agent_credential_valid:false`,
`reproduced:false`, never `null`): an honest engine refuses such an intent and
never signs a decision for it. The D12 evaluator-version check (§ above) runs
**before** the admission gate on replay — a foreign-evaluator artifact stays
"could not be attempted" (`reproduced:null`) even if its credential is also
invalid, because admission rules are themselves versioned semantics. The
standalone `verifier/verify.mjs` is unchanged: it answers **authenticity**
only and deliberately does not re-verify embedded credentials.
