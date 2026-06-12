# AGENTS.md — how an AI agent consumes this API

**Scope note:** this file documents how AI agents **consume this service's HTTP
API at runtime** (reading decisions, halting, escalating). It is *not* a set of
repository build instructions for coding agents — contributor setup and
conventions live in [`CONTRIBUTING.md`](./CONTRIBUTING.md).

> **UNCERTIFIED — synthetic demo rule pack.** Every decision this service
> returns today comes from a **synthetic demo rule pack** — **not a fatwa /
> not certified / not production advice**. Its envelopes are
> **committee-reviewable demo evidence**. Send **synthetic data only**: never
> real card, customer, or personal data.

The full normative contract, with every problem type and real captured
examples, is [`docs/machine-contract.md`](./docs/machine-contract.md). This
page is the condensed version an agent needs at integration time.

## The two rules

1. **A decision is ALWAYS HTTP 200 — read `body.decision`, never the status
   code.** A `deny` is a 200. A 200 is not "approved"; it means "a decision
   exists and is signed".
2. **A 4xx is NEVER a decision.** It is an RFC 9457 `application/problem+json`
   integration failure: no decision was made, no envelope exists, nothing was
   signed. Fix the request; do not reissue it blindly; never record it as a
   deny.

## What each decision requires

| `body.decision` | Behavior |
|---|---|
| `"allow"` | Proceed. Retain `evidence_artifact` as the audit record. |
| `"deny"` | **Halt. Do not retry.** The evaluator is deterministic — no LLM, no clock, no randomness — so the same intent against the same `rule_pack_hash` re-derives the same `deny` on every attempt. Retrying cannot change the outcome. |
| `"review"` | **Halt and escalate to a human**, passing along `decision_id`, `reason_codes`, and `evidence_artifact`. Never downgrade a `review` to an allow or a deny on your own. |

## Worked example: reading a deny

Request (synthetic casino-hotel scenario):

```sh
curl -s http://127.0.0.1:8787/authorize \
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

Real response — **HTTP 200** (fields trimmed; full capture in the machine
contract):

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
      "standards_ref": { "status": "pending", "note": "pending — populated on v1.0 certification" }
    }
  ],
  "decision_id": "ev-03e70853-30d1-47a0-995f-3a5a47108ca9",
  "rule_pack_id": "shariah",
  "rule_pack_version": "0.1.1",
  "rule_pack_hash": "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4",
  "rule_pack_status": "uncertified",
  "evidence_artifact": "eyJhbGciOiJFZERTQSIsImtpZCI6…(JWS-compact)"
}
```

Correct agent behavior, step by step:

1. Status is `200` → a decision exists. Parse the body.
2. `decision` is `"deny"` → **halt the payment flow now**.
3. **Do not retry.** Same intent + same `rule_pack_hash` = same `deny`,
   deterministically. There is no "trying again later" for a compliance
   prohibition; only a *changed intent* (or a new rule-pack version) can
   change the decision.
4. Record `reason_codes` (`["MAYSIR"]` — the closed-set code for gambling) and
   keep `evidence_artifact`: it is the signed, offline-verifiable record of
   exactly this decision.
5. Note `rule_pack_status: "uncertified"` — the machine-readable honesty
   marker, present on every response.

## On a 4xx: fix the request, don't reissue blindly

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

Use `issues[].field` / `issues[].message` (and `allowed_values` when present)
to repair the request, then submit the corrected intent. Resending identical
bytes deterministically reproduces the identical 4xx. The schema is strict on
purpose: nothing is coerced, unknown fields are rejected — a compliance
decision is never made on silently-repaired input. Other 4xx you may meet:
`422 unknown-profile` (the body lists `available_profiles`), `400
invalid-unicode`, `413` body too large, `404`s — all catalogued in
[`docs/machine-contract.md`](./docs/machine-contract.md).

## Verifying what you were told (optional but cheap)

The envelope is independently checkable — no key material, no server trust:

```sh
node verifier/verify.mjs --evidence evidence.jws --jwks jwks.json   # authenticity
npm run replay -- --evidence evidence.jws --pack pack.json          # reproducibility
```

`GET /.well-known/jwks.json` serves the verifying keys;
`GET /rule-packs/:id/:version` serves the exact canonical pack bytes cited by
`rule_pack_hash`. See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

## Pointers

- Normative contract: [`docs/machine-contract.md`](./docs/machine-contract.md)
- Deterministic evaluation semantics: [`docs/evaluator-semantics.md`](./docs/evaluator-semantics.md)
- Five-minute tutorial: [`docs/getting-started.md`](./docs/getting-started.md)
- Machine-readable index of these docs: [`llms.txt`](./llms.txt)
