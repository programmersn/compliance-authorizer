# Reason codes — the closed decision vocabulary

This page is the **closed reference** for the two machine-readable verdict
channels of `POST /authorize`:

1. **`reason_codes`** — the codes that travel **on a decision** (`allow` /
   `deny` / `review`, always HTTP 200 + a signed envelope). This set is
   **closed**: every value below is enumerated here, drawn directly from the
   loaded rule pack and the engine. There are **no free-text reason codes** —
   a code your integration does not recognize is a code that does not exist at
   this version.
2. **Problem `type` URIs** — the identifiers that travel **on an integration
   failure** (a 4xx/5xx RFC 9457 `problem+json`, **never** a decision, **never**
   signed). These are the actionable failure contract.

The split between the two is the **`error ≠ deny`** invariant, stated once and
binding everywhere: a `deny` is a *signed compliance finding* (200); a 4xx is
*your request needs fixing* (no decision was made, no envelope exists). The two
are never collapsed into one channel. See
[`docs/machine-contract.md`](./machine-contract.md) for the always-200 / 4xx
contract in full, and [`docs/evaluator-semantics.md`](./evaluator-semantics.md)
for the exact decision semantics this page indexes.

> **UNCERTIFIED — synthetic demo rule pack.** Every reason code below is emitted
> by a **synthetic demo rule pack** — **not a fatwa / not certified / not
> production advice**. The category mappings (which MCC means "gambling", the 5%
> mixed-revenue threshold) are **synthetic demo assignments**, illustrative and
> not a certified screening standard. The envelopes are **committee-reviewable
> demo evidence**. A certified version *would* additionally carry a standard
> citation in each rule's `standards_ref` and a scholar signature over the rule
> pack's hash — this demo carries an explicit `pending` / `uncertified` slot in
> their place. Scenario labels are generic synthetic placeholders
> ("casino-hotel", "mixed-revenue ETF", "subscription"); no real merchant,
> customer, scholar, institution, or PII appears anywhere.

The set documented here is for **profile `shariah-v0.1`**, rule pack
`shariah@0.1.1` (`rule_pack_hash`
`5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4`), evaluator
`0.2.0`. Reason codes are **pack data plus one engine code**; a future pack
version may add or rename pack-level codes (and would carry a new hash), so a
consumer pins the `rule_pack_hash` it integrated against.

---

## How a reason code is produced (so the closed set is verifiable, not asserted)

- **Pack-level codes** are read verbatim from the rule pack's `rules[].reason_code`
  field (`rule-packs/shariah/0.1.1.json`). The evaluator
  (`src/rules/evaluator.ts`) emits the codes of the rules that **matched**,
  **de-duplicated and in pack order** — it invents nothing. An intent that
  matches no rule falls through to the pack's `default_decision` (`allow` for
  this demo pack) with an **empty** `reason_codes` array.
- **The one engine-level code** (`AGENT_SCOPE_EXCEEDED`) is defined in code, not
  in any pack (`src/vc/enforce.ts`). It is appended only when an intent carries a
  **valid** `agent_credential` whose allowed-MCC scope excludes the intent's
  `merchant.mcc`.
- **Multiple codes** can co-occur on one decision (e.g. a pack `deny` plus a
  scope exclusion). The decision itself is `most_restrictive` across all matched
  signals under the fixed engine severity **`deny` > `review` > `allow`**.

Because the evaluator is a pure, deterministic function — **no LLM, no clock, no
randomness, no I/O** — the same intent against the same `rule_pack_hash` +
`evaluator_version` always re-derives the same decision and the same
`reason_codes`. The test suite pins each code to its exact decision; nothing here
is free-text or model-generated.

---

## The closed reason-code set

| `reason_code` | Layer | Decision | Emitting rule(s) / source |
|---|---|---|---|
| `MAYSIR` | rule pack | `deny` | `MAYSIR-MCC`, `MAYSIR-ATTR` |
| `INTOXICANTS` | rule pack | `deny` | `INTOXICANTS-MCC`, `INTOXICANTS-ATTR` |
| `RIBA` | rule pack | `deny` | `RIBA-MCC`, `RIBA-ATTR` |
| `GHARAR` | rule pack | `review` | `GHARAR-ATTR` |
| `MIXED_REVENUE` | rule pack | `review` | `MIXED-REVENUE` |
| `AGENT_SCOPE_EXCEEDED` | credential scope (engine) | `deny` | `src/vc/enforce.ts` |

An `allow` carries an **empty** `reason_codes` array: it is the absence of any
matched prohibition or review rule (and, when a credential is present, an
in-scope MCC), not a code in its own right.

### `MAYSIR` — gambling

- **Layer:** rule pack (`MAYSIR-MCC`, `MAYSIR-ATTR`).
- **Decision it drives:** `deny`.
- **Plain language (committee-readable):** *The payment is to a gambling,
  betting, lottery, or casino merchant, or the merchant data flags gambling
  activity (for example a casino operating inside a hotel). Maysir (gambling) is
  prohibited, so the agent is stopped.*
- **What triggers it:** `merchant.mcc` is one of `7995`, `7800`, `7801`, `7802`
  (the `MAYSIR-MCC` rule), **or** `merchant.attributes` includes the token
  `"gambling"` (the `MAYSIR-ATTR` rule — this catches a gambling line of
  business even when the primary MCC is permissible, e.g. a hotel MCC).
- **Honest synthetic example:** an agent tries to pay a *casino-hotel*
  (`"mcc": "7011"`, `"attributes": ["hotel","casino","gambling"]`). The MCC is a
  permissible hotel category, but `MAYSIR-ATTR` matches the `"gambling"`
  attribute → `deny`, `reason_codes: ["MAYSIR"]`. (Both `MAYSIR-*` rules share
  the one code, so even if both matched the code appears once.)

### `INTOXICANTS` — alcohol / intoxicants

- **Layer:** rule pack (`INTOXICANTS-MCC`, `INTOXICANTS-ATTR`).
- **Decision it drives:** `deny`.
- **Plain language (committee-readable):** *The payment is to a bar, tavern,
  nightclub, or package store selling intoxicants, or the merchant data flags
  alcohol or another intoxicant as a material line of business. Intoxicants are
  prohibited, so the agent is stopped.*
- **What triggers it:** `merchant.mcc` is `5813` or `5921` (the `INTOXICANTS-MCC`
  rule), **or** `merchant.attributes` includes the token `"alcohol"` (the
  `INTOXICANTS-ATTR` rule).
- **Honest synthetic example:** an agent tries to pay a package store
  (`"mcc": "5921"`). `INTOXICANTS-MCC` matches → `deny`,
  `reason_codes: ["INTOXICANTS"]`.

### `RIBA` — interest

- **Layer:** rule pack (`RIBA-MCC`, `RIBA-ATTR`).
- **Decision it drives:** `deny`.
- **Plain language (committee-readable):** *The payment is to an interest-bearing
  cash-advance or credit facility, or the merchant data flags an interest-bearing
  credit product. Riba (interest) is prohibited, so the agent is stopped.*
- **What triggers it:** `merchant.mcc` is `6010` or `6011` (the `RIBA-MCC` rule —
  a synthetic demo mapping for an interest-bearing cash-disbursement facility),
  **or** `merchant.attributes` includes the token `"interest-bearing-credit"`
  (the `RIBA-ATTR` rule).
- **Honest synthetic example:** an agent tries to draw on an interest-bearing
  cash-advance merchant (`"mcc": "6010"`). `RIBA-MCC` matches → `deny`,
  `reason_codes: ["RIBA"]`.

### `GHARAR` — excessive uncertainty / speculation

- **Layer:** rule pack (`GHARAR-ATTR`).
- **Decision it drives:** `review` (not `deny`).
- **Plain language (committee-readable):** *The merchant or instrument data flags
  speculative derivatives. Gharar (excessive uncertainty) is not auto-approved
  and not auto-denied — the case is held for a person on your committee to take
  over.*
- **What triggers it:** `merchant.attributes` includes the token
  `"speculative-derivatives"` (the `GHARAR-ATTR` rule).
- **Honest synthetic example:** an agent routes a payment to a merchant whose
  attributes include `"speculative-derivatives"`. `GHARAR-ATTR` matches →
  `review`, `reason_codes: ["GHARAR"]`. The agent must **halt and escalate**, not
  proceed and not retry.

### `MIXED_REVENUE` — mixed impermissible revenue above the demo threshold

- **Layer:** rule pack (`MIXED-REVENUE`).
- **Decision it drives:** `review` (not `deny`).
- **Plain language (committee-readable):** *Screening data reports an
  impermissible revenue share at or above the demo threshold (5%). The threshold
  is illustrative, not a certified screening standard, so the case is held for
  human review rather than approved automatically.*
- **What triggers it:** `screening.mixed_revenue_ratio` is **greater than or
  equal to** `0.05` (the `MIXED-REVENUE` rule, operator `gte`). The 5% figure is
  a **synthetic demo threshold**, explicitly not a certified screening standard.
- **Honest synthetic example:** an agent rebalances into a *mixed-revenue ETF*
  whose screening reports an 8% impermissible share
  (`"screening": { "mixed_revenue_ratio": 0.08 }`). `MIXED-REVENUE` matches →
  `review`, `reason_codes: ["MIXED_REVENUE"]`.

### `AGENT_SCOPE_EXCEEDED` — agent credential out of scope

- **Layer:** credential scope (**engine-level**, `src/vc/enforce.ts` — joins the
  closed set but is defined by **no** pack).
- **Decision it drives:** `deny` — a **signed** deny (HTTP 200 + envelope). A
  valid credential whose scope excludes the MCC is a *decision*, not an error.
- **Plain language (committee-readable):** *The agent presented a valid signed
  credential, but that credential only authorizes a fixed list of merchant
  categories, and this payment's category is not on the list. The agent acted
  outside the authority it was granted, so the payment is stopped.*
- **What triggers it:** the intent carries an **OPTIONAL** `agent_credential` (a
  synthetic signed `did:key` credential, `credential_type`
  `synthetic-agent-mcc-scope/0.1`, scope shape `{ allowed_mcc: [<4-digit>, …] }`)
  that **verifies**, and the intent's `merchant.mcc` is **not** an element of the
  credential's `allowed_mcc`. The engine combines this scope layer with the rule
  pack `most_restrictive`ly: a scope `deny` beats every pack decision, so the
  final decision is always `deny` and `AGENT_SCOPE_EXCEEDED` is appended to the
  pack's `reason_codes` (de-duplicated). An **absent or non-string**
  `merchant.mcc` never passes the scope screen (the same missing-field rule as
  the evaluator) — it reads as out of scope.
- **Honest synthetic example:** an agent holds a credential scoped to
  `{ "allowed_mcc": ["5411","5499"] }` (grocery only) and tries to pay a clean
  subscription merchant (`"mcc": "5968"`) that the rule pack alone would `allow`.
  The credential is valid, but `5968` is not in scope → `deny`,
  `reason_codes: ["AGENT_SCOPE_EXCEEDED"]`. If the same out-of-scope intent ALSO
  hit a pack prohibition (say `MAYSIR`), both codes appear:
  `reason_codes: ["MAYSIR","AGENT_SCOPE_EXCEEDED"]`, decision `deny`.

> **Not in this list — by design.** An *invalid* `agent_credential` (malformed,
> tampered, alg-confused, wrong issuer, bad payload schema) is **never** a reason
> code and **never** a `deny`. It is an integration failure: a `422`
> problem+json (`…/problems/invalid-agent-credential`, below), no envelope is
> signed. `AGENT_SCOPE_EXCEEDED` is the *valid-but-out-of-scope* case; the
> *invalid-credential* case is the opposite category. This boundary is the
> `error ≠ deny` invariant applied to credentials.

---

## The actionable failure contract — problem `type` URIs

When the request itself is broken, the service answers with an RFC 9457
`application/problem+json` document and a 4xx (or 5xx) status. By construction
(the problem module never touches the signing key): **no decision was made, no
evidence envelope exists, nothing was signed.** Every problem `detail` states
this explicitly. **A 4xx must never be read as `deny`.** The correct machine
behavior is to **fix the request** (the problem document names what is wrong),
then resubmit; re-issuing the identical bytes deterministically reproduces the
identical 4xx.

Service-specific `type` URIs live under
`https://github.com/programmersn/compliance-authorizer/problems/<slug>`
(`PROBLEM_TYPE_BASE` in `src/http/problem.ts`; rendered `…/problems/<slug>`
below). Framework-level rejections use the RFC 9457 default `about:blank`.

| Status | `type` | When it fires | Route(s) | Detail / extension shape |
|---|---|---|---|---|
| `400` | `…/problems/invalid-request-body` | The body parses as JSON but fails the strict TypeBox schema — wrong type, missing required field, or an unknown extra field. Nothing is coerced or stripped. | `POST /authorize`, `POST /verify` | `issues[]`: each `{ field, message }` (JSON-pointer `field`, e.g. `/merchant/mcc`; `(body root)` for top-level problems), plus `allowed_values` where the schema constrains an enum. |
| `400` | `…/problems/invalid-unicode` | The intent contains a lone UTF-16 surrogate — syntactically valid JSON that RFC 8785 §3.2.2.2 forbids canonicalizing, so no signable evidence can exist. | `POST /authorize` | `detail` only (no machine extension). |
| `422` | `…/problems/invalid-agent-credential` | The intent carries an `agent_credential` that **failed verification** (malformed JWS, `alg` ≠ `EdDSA`, unresolvable / mismatched `did:key` issuer, bad signature, or a non-canonical / schema-invalid payload). An **invalid** credential is an integration failure, never a `deny`. | `POST /authorize` | `credential_error`: one of `malformed`, `alg_rejected`, `issuer_invalid`, `signature_invalid`, `payload_invalid` (`AgentCredentialErrorCode` in `src/vc/verify.ts`). |
| `422` | `…/problems/unknown-profile` | The intent is well-formed but names a compliance profile this engine has not loaded. | `POST /authorize` | `available_profiles[]`: the profiles this engine does serve (e.g. `["shariah-v0.1"]`). |
| `404` | `…/problems/rule-pack-not-found` | The requested rule pack id/version is not served by this engine. | `GET /rule-packs/:id/:version` | `detail` only. |
| `400` | `about:blank` ("Request rejected before evaluation") | The body is not parseable JSON at all (or otherwise fails in the framework before validation). | any body route | `detail` only (framework message + the no-envelope guarantee). |
| `413` | `about:blank` ("Request rejected before evaluation") | The body exceeds the pinned 1 MiB cap. | any body route | `detail` only. |
| `404` | `about:blank` ("Not found") | No route matches the method + path. | anywhere | `detail` names the method + path. |
| `500` | `about:blank` ("Internal error") | The service itself failed. Same guarantee: no decision, no envelope. | anywhere | `detail` only. |

### The offending-field / allowed-values detail shape (machine-actionable)

For `…/problems/invalid-request-body`, the `issues` array is the
machine-actionable part. Each issue names the **offending field** (JSON-pointer;
`(body root)` for top-level problems such as an unknown extra field) and, where
the schema constrains values, an `allowed_values` list. Captured example —
`merchant.mcc` sent as a number where the schema requires a 4-digit *string*:

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/invalid-request-body",
  "title": "Request body failed schema validation",
  "status": 400,
  "detail": "The request body failed schema validation. No decision was made and no evidence envelope exists for this request.",
  "issues": [
    { "field": "/merchant/mcc", "message": "must be string" }
  ]
}
```

For `…/problems/invalid-agent-credential`, the `credential_error` extension lets
an integration distinguish the verification stage that rejected the credential
without parsing prose:

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/invalid-agent-credential",
  "title": "Invalid agent credential",
  "status": 422,
  "detail": "The payment intent presents an agent credential that failed verification: …. No decision was made and no evidence envelope exists for this request.",
  "credential_error": "signature_invalid"
}
```

---

## The verification path keeps the same boundary

`POST /verify` obeys the identical split: a **well-formed** verification request
is always HTTP 200 and the body carries the verdict. `{"valid": false}` — an
inauthentic artifact — is a *finding*, exactly like a `deny`, and is therefore a
`200`, never a 4xx. Only a malformed request body (missing field, wrong type,
unknown extra field) is a `400 …/problems/invalid-request-body`. The offline
tools keep the same boundary in exit codes: a verdict is exit `0`/`1`, an
operator/input error (unreadable file, bad usage) is exit `2` — see
[`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md).

---

## The contract in one paragraph

`reason_codes` is a **closed set** of exactly six values
(`MAYSIR`, `INTOXICANTS`, `RIBA` → `deny`; `GHARAR`, `MIXED_REVENUE` →
`review`; `AGENT_SCOPE_EXCEEDED` → `deny`); there are **no free-text codes**, and
an `allow` carries none of them. Reason codes ride **only on a decision** (HTTP
200 + signed envelope). Everything in the problem-type table rides **only on an
integration failure** (4xx/5xx problem+json, no envelope) and must **never** be
read as a `deny`. That separation is the `error ≠ deny` invariant; it is
enforced structurally (the problem path cannot reach the signing key) and pinned
by tests that assert each decision's exact `reason_codes` and each 4xx path's
exact problem shape.

## See also

- [`docs/machine-contract.md`](./machine-contract.md) — the normative always-200
  / 4xx contract, with live request/response captures.
- [`docs/evaluator-semantics.md`](./evaluator-semantics.md) — the exact,
  versioned decision semantics (operators, missing-field rule, two-layer scope
  combination) these codes index.
- [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) — verify and replay any decision
  offline, trusting nothing.
- [`rule-packs/shariah/0.1.1.json`](../rule-packs/shariah/0.1.1.json) — the
  source of every pack-level reason code above.
