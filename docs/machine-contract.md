# The machine contract — how software must read this API

This page is the **normative contract** for any program (an AI agent, a payment
orchestrator, a test harness) that consumes this service. It has exactly two
halves, and **both carry equal weight** — reading only one of them produces the
two worst integration bugs this API can suffer:

| Half | The rule | The bug it prevents |
|---|---|---|
| **A. A decision is always HTTP 200** | `allow`, `deny`, and `review` are all `200` + a **signed** envelope. Read `body.decision`, **never** the status code. | An agent sees `200` on a `deny` and reads "request succeeded" as "payment approved". |
| **B. A 4xx is never a decision** | An integration failure is RFC 9457 `application/problem+json`. **No decision was made, no envelope exists**, nothing was signed. | An agent (or a dashboard) reads a `400` as "the payment was denied". |

One sentence to memorize: **the status code answers "did the integration
work?"; `body.decision` answers "what is the compliance decision?"** The two
questions are never collapsed into one channel.

> **UNCERTIFIED — synthetic demo rule pack.** Every decision shown on this page
> was produced by a **synthetic demo rule pack** — **not a fatwa / not certified
> / not production advice**. The envelopes are **committee-reviewable demo
> evidence**. Scenario labels are generic synthetic placeholders ("casino-hotel",
> "mixed-revenue ETF", "subscription"); no real merchant, customer, or PII
> appears anywhere. A certified version *would* additionally carry standard
> citations and a scholar signature over the rule pack's hash — this demo
> carries an explicit `uncertified` slot in their place.

All examples below are **real request/response pairs captured from a running
server** (`npm run dev`, v0.3.0.0, Shariah v0.1 demo pack `shariah@0.1.1`).
Hashes, ids, and signatures are genuine; only long JWS strings are elided where
marked.

---

## Half A — a decision is ALWAYS HTTP 200

`POST /authorize` evaluates a payment intent against the loaded rule pack and
returns **HTTP 200 for every decision**, including `deny`. The body carries the
decision, its reason codes, the matched rules, and a signed evidence envelope
(`evidence_artifact`, JWS-compact over RFC 8785 canonical JSON).

### What each decision requires of the caller

| `body.decision` | Meaning | Required machine behavior |
|---|---|---|
| `"allow"` | No rule matched, or the pack's precedence resolved to allow. | Proceed with the payment flow. Keep `evidence_artifact`. |
| `"deny"` | A prohibition rule matched (see `reason_codes`). | **Halt. Do not retry.** The evaluator is deterministic — no LLM, no clock, no randomness — so the same intent against the same `rule_pack_hash` re-derives the same `deny` every time. Re-submitting an unchanged intent cannot change the outcome; it only produces another signed `deny`. |
| `"review"` | A rule matched that routes the case to a human (e.g. a screening threshold). | **Halt and escalate to a human.** `review` is not a soft allow and not a soft deny — it is a decision that a person must take over. Do not proceed, do not auto-retry, do not downgrade it to either of the other two. |

### Worked example: a `deny` is HTTP 200 (casino-hotel)

Request — an agent tries to pay a casino-hotel merchant:

```sh
curl -s -w "\nHTTP %{http_code}\n" http://127.0.0.1:8787/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "shariah-v0.1",
    "merchant": {
      "name": "casino-hotel",
      "mcc": "7011",
      "attributes": ["hotel", "casino", "gambling"]
    },
    "amount": { "value": 420, "currency": "EUR" }
  }'
```

Real response — **status `200`**, content type `application/json`:

```json
{
  "decision": "deny",
  "reason_codes": ["MAYSIR"],
  "matched_rules": [
    {
      "rule_id": "MAYSIR-ATTR",
      "reason_code": "MAYSIR",
      "decision": "deny",
      "title": "Gambling exposure in merchant attributes",
      "description": "Merchant attribute data flags gambling activity (e.g. a casino operation inside a hotel). Maysir (gambling) is prohibited even when the primary merchant category is permissible.",
      "standards_ref": {
        "status": "pending",
        "note": "pending — populated on v1.0 certification"
      }
    }
  ],
  "decision_id": "ev-03e70853-30d1-47a0-995f-3a5a47108ca9",
  "decision_timestamp": "2026-06-12T14:09:00.528Z",
  "rule_pack_id": "shariah",
  "rule_pack_version": "0.1.1",
  "rule_pack_hash": "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4",
  "rule_pack_status": "uncertified",
  "evaluator_version": "0.2.0",
  "intent_hash": "9cc65d49e4ac6df696f26b41a95c8465f3556228eb249c54634980a5dc682c31",
  "envelope_version": "0.1.0",
  "evidence_artifact": "eyJhbGciOiJFZERTQSIsImtpZCI6ImhUVDVvemlCVThLcGN2MVdVaDlpdFp3cmQwYzd6SXF2UW5hcXR5Y0xBUzQifQ.eyJkZWNpc2lvbiI6ImRlbnkiLCJkZWNpc2lvbl9pZCI6… (JWS-compact, elided)"
}
```

```
HTTP 200
```

Read it correctly: the **integration succeeded** (200) and the **compliance
decision is `deny`** (`body.decision`). The agent must halt and must not retry.
The `evidence_artifact` is the signed, tamper-evident record of exactly this
decision — it verifies offline (see below). The `rule_pack_status:
"uncertified"` field is the machine-readable honesty marker, present on every
response without decoding anything.

### Worked example: a `review` is HTTP 200 (mixed-revenue ETF)

Request — an agent rebalances into a mixed-revenue ETF whose screening data
reports an 8% impermissible revenue share:

```sh
curl -s http://127.0.0.1:8787/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "shariah-v0.1",
    "merchant": { "name": "mixed-revenue ETF", "mcc": "6211", "attributes": ["fund"] },
    "amount": { "value": 1000, "currency": "EUR" },
    "screening": { "instrument": "etf", "mixed_revenue_ratio": 0.08 }
  }'
```

Real response (status `200`; `evidence_artifact` elided):

```json
{
  "decision": "review",
  "reason_codes": ["MIXED_REVENUE"],
  "matched_rules": [
    {
      "rule_id": "MIXED-REVENUE",
      "reason_code": "MIXED_REVENUE",
      "decision": "review",
      "title": "Mixed impermissible revenue share above demo threshold",
      "description": "Screening data reports an impermissible revenue share at or above the synthetic demo threshold of 5%. The threshold is illustrative, not a certified screening standard; the case is routed to human review.",
      "standards_ref": {
        "status": "pending",
        "note": "pending — populated on v1.0 certification"
      }
    }
  ],
  "decision_id": "ev-a6412fcb-77f2-401d-928c-d1d36c037208",
  "decision_timestamp": "2026-06-12T14:09:01.025Z",
  "rule_pack_id": "shariah",
  "rule_pack_version": "0.1.1",
  "rule_pack_hash": "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4",
  "rule_pack_status": "uncertified",
  "evaluator_version": "0.2.0",
  "intent_hash": "8a3e852358e8b3864b8d51210cdbb14fcc6472518003cda127bb59b07267e24e",
  "envelope_version": "0.1.0",
  "evidence_artifact": "… (JWS-compact, elided)"
}
```

The agent halts and routes the case — with its `decision_id` and
`evidence_artifact` — to a human. An `allow` (e.g. the same request with a
clean subscription merchant: `"mcc": "5968"`, no flagged attributes) has the
identical 200 shape with `"decision": "allow"`, empty `reason_codes`, and empty
`matched_rules`.

### Reference consumption logic

```js
const res = await fetch("http://127.0.0.1:8787/authorize", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(intent),
});

if (res.status === 200) {
  // Half A: a decision exists and is signed. NEVER infer it from the status.
  const body = await res.json();
  switch (body.decision) {
    case "allow":  /* proceed; retain body.evidence_artifact */            break;
    case "deny":   /* HALT. Do NOT retry — deterministic engine. */        break;
    case "review": /* HALT. Escalate to a human with the envelope. */      break;
  }
} else {
  // Half B: an integration failure. NO decision was made, NOTHING was signed.
  const problem = await res.json(); // application/problem+json (RFC 9457)
  // Fix the request using problem.detail / problem.issues, then resubmit.
  // NEVER treat this branch as a deny, and never retry the same bytes blindly.
}
```

---

## Half B — a 4xx is an integration failure, NEVER a signed decision

When the request itself is broken — malformed JSON, a schema violation, an
unknown profile, an oversized body — the service answers with an **RFC 9457
`application/problem+json`** document and a 4xx status. Three things are
guaranteed, by construction (the problem path cannot reach the signing key):

1. **No decision was made.** The intent never reached the evaluator, or could
   not be canonicalized into evidence.
2. **No evidence envelope exists.** Nothing was signed; there is nothing to
   verify, store, or display. Every problem `detail` states this explicitly.
3. **A 4xx must never be read as `deny`.** A deny is a *signed compliance
   finding*; a 4xx is *your request needs fixing*. Collapsing them corrupts
   both the agent's behavior and the audit trail.

The correct machine behavior on any 4xx: **fix the request** (the problem
document names what is wrong), then submit the corrected intent. Re-issuing the
identical bytes will deterministically produce the identical 4xx.

### The problem types this service actually emits

Service-specific problem `type` URIs live under
`https://github.com/programmersn/compliance-authorizer/problems/<slug>`
(rendered `…/problems/<slug>` below). Framework-level rejections use the RFC
9457 default `about:blank`. All captured live:

| Status | `type` | When | Route |
|---|---|---|---|
| `400` | `…/problems/invalid-request-body` | The body parses as JSON but fails the strict TypeBox schema (wrong type, missing field, unknown extra field — nothing is coerced or stripped). | `POST /authorize`, `POST /verify` |
| `400` | `…/problems/invalid-unicode` | The intent contains a lone UTF-16 surrogate — syntactically valid JSON that RFC 8785 §3.2.2.2 forbids canonicalizing, so no signable evidence can exist for it. | `POST /authorize` |
| `400` | `about:blank` ("Request rejected before evaluation") | The body is not parseable JSON at all (or otherwise dies in the framework before validation). | any body route |
| `413` | `about:blank` ("Request rejected before evaluation") | The body exceeds the pinned 1 MiB cap. | any body route |
| `422` | `…/problems/unknown-profile` | The intent is well-formed but names a compliance profile this engine has not loaded. The response lists `available_profiles`. | `POST /authorize` |
| `422` | `…/problems/invalid-agent-credential` | The intent carries an OPTIONAL `agent_credential` that **failed verification** (malformed JWS, `alg` ≠ `EdDSA`, unresolvable / mismatched `did:key` issuer, bad signature, or a non-canonical / schema-invalid payload). The `credential_error` extension names which (`malformed`, `alg_rejected`, `issuer_invalid`, `signature_invalid`, `payload_invalid`). An **invalid** credential is an integration failure, never a `deny`. | `POST /authorize` |
| `404` | `…/problems/rule-pack-not-found` | The requested rule pack id/version is not served by this engine. | `GET /rule-packs/:id/:version` |
| `404` | `about:blank` ("Not found") | No route matches the method + path. | anywhere |
| `500` | `about:blank` ("Internal error") | The service itself failed. Same guarantee: no decision, no envelope. | anywhere |

### Real captured examples

**`400 invalid-request-body`** — `merchant.mcc` sent as a number (the schema
requires a 4-digit *string*, so `"0742"`-style leading zeros survive):

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

The `issues` array is the machine-actionable part: it names the offending field
(JSON-pointer style; `(body root)` for top-level problems such as an unknown
extra field) and, where the schema constrains values, an `allowed_values` list.

**`400 invalid-unicode`** — a lone surrogate (`"\ud800"`) in a string field:

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/invalid-unicode",
  "title": "Intent contains invalid Unicode",
  "status": 400,
  "detail": "The payment intent contains invalid Unicode (a lone UTF-16 surrogate) that cannot be canonicalized per RFC 8785 §3.2.2.2. No decision was made and no evidence envelope exists for this request."
}
```

**`400 about:blank`** — the body is not JSON:

```json
{
  "type": "about:blank",
  "title": "Request rejected before evaluation",
  "status": 400,
  "detail": "Body is not valid JSON but content-type is set to 'application/json'. No decision was made and no evidence envelope exists for this request."
}
```

**`413 about:blank`** — the body exceeds the 1 MiB cap:

```json
{
  "type": "about:blank",
  "title": "Request rejected before evaluation",
  "status": 413,
  "detail": "Request body is too large. No decision was made and no evidence envelope exists for this request."
}
```

**`422 unknown-profile`** — a well-formed intent for a profile this engine does
not serve:

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/unknown-profile",
  "title": "Unknown compliance profile",
  "status": 422,
  "detail": "Profile \"no-such-profile\" is not loaded on this engine. No decision was made and no evidence envelope exists for this request.",
  "available_profiles": ["shariah-v0.1"]
}
```

**`422 invalid-agent-credential`** — an intent whose optional `agent_credential`
fails verification (here a tampered signature). The `credential_error` extension
names the defect; **no envelope is signed** (error ≠ deny):

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/invalid-agent-credential",
  "title": "Invalid agent credential",
  "status": 422,
  "detail": "The payment intent presents an agent credential that failed verification: agent-credential Ed25519 signature does not verify — the credential was tampered with or was not issued by this did:key. No decision was made and no evidence envelope exists for this request.",
  "credential_error": "signature_invalid"
}
```

**`404 rule-pack-not-found`** — `GET /rule-packs/shariah/9.9.9`:

```json
{
  "type": "https://github.com/programmersn/compliance-authorizer/problems/rule-pack-not-found",
  "title": "Rule pack not found",
  "status": 404,
  "detail": "No rule pack shariah@9.9.9 is served by this engine."
}
```

**`404 about:blank`** — no such route (`GET /no-such-route`):

```json
{
  "type": "about:blank",
  "title": "Not found",
  "status": 404,
  "detail": "No route matches GET /no-such-route."
}
```

---

## The optional agent credential (two-layer intents)

`POST /authorize` accepts an OPTIONAL `agent_credential` field on the payment
intent: a JWS-compact, `did:key`-issued credential carrying an allowed-MCC
scope. It changes nothing about the always-200 contract above — it only adds a
second, most-restrictive layer:

- **No credential** → the rule-pack decision verbatim (unchanged from before).
- **Valid credential, MCC in scope** → the rule-pack decision verbatim.
- **Valid credential, MCC out of scope** → a **SIGNED `deny` (HTTP 200 +
  envelope)** carrying the engine-level reason code `AGENT_SCOPE_EXCEEDED`. A
  decision, not an error: `deny` = halt, do not retry.
- **Invalid credential** (any verification failure) → **`422
  invalid-agent-credential`** problem+json, no envelope (the table row above).
  error ≠ deny: an invalid credential is an integration failure, never a `deny`.

The credential is a **constraint, not an authorization**: it can only narrow a
decision, never widen it, so a self-issued credential confers no privilege (see
[`evaluator-semantics.md` §7.5](./evaluator-semantics.md)). It lives inside
`payment_intent`, so `intent_hash` covers it and offline replay re-verifies it
with no extra inputs (`did:key` is self-certifying). Full semantics:
[`evaluator-semantics.md` §7](./evaluator-semantics.md); the reason code and
problem shape: [`reason-codes.md`](./reason-codes.md).

## The same split on the verification path

`POST /verify` obeys the identical contract: a **well-formed** verification
request is always HTTP 200, and the body carries the verdict. `{"valid":
false}` — an inauthentic artifact — is a *finding*, exactly like a `deny`, and
is therefore a 200, never a 4xx. Only a malformed request body (missing field,
wrong type, unknown extra field) is a `400 invalid-request-body` problem. The
offline tools keep the same boundary in exit codes: a verdict is exit `0`/`1`,
an operator error (unreadable file, bad usage) is exit `2` — see
[`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md).

## Why this contract is trustworthy, not just asserted

- **Determinism** (the reason `deny` means halt-no-retry): the evaluator is a
  pure function — no LLM, no clock, no randomness, no I/O. Same intent + same
  `rule_pack_hash` + same `evaluator_version` always re-derives the same
  decision. [`docs/evaluator-semantics.md`](./evaluator-semantics.md) pins the
  exact semantics.
- **Structural separation**: the problem+json module never touches the signing
  key; only a decision can be signed. There is no code path on which an
  integration failure produces an envelope.
- **Independent verification**: the `deny` captured above was re-verified
  offline while writing this page — `node verifier/verify.mjs --evidence … --jwks
  … --pack …` returned `RESULT: PASS — decision "deny" (["MAYSIR"])`, exit `0`,
  with zero trust in the server.
- **Tests assert exact decisions**: the suite pins `deny` → HTTP 200 + exact
  `reason_codes`, and every 4xx path above to its problem shape.

## See also

- [`AGENTS.md`](../AGENTS.md) + [`llms.txt`](../llms.txt) — the condensed
  agent-facing version of this contract.
- [`docs/getting-started.md`](./getting-started.md) — clone to first signed
  decision in five minutes.
- [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) — verify and replay any
  decision offline, trusting nothing.
- [`docs/agt-mapping.md`](./agt-mapping.md) — projecting this decision model
  onto a governance-toolkit policy shape.
