# AGT mapping — projecting this engine onto a `governance.toolkit/v1` policy shape

**Status: schema-mapped, not engine-verified.** This document maps the
compliance-authorizer's decision/evidence model onto the document shape used by
agent-governance-toolkit (AGT) style policy engines (`apiVersion:
governance.toolkit/v1`). The mapping is a **paper projection**: we have **not**
validated the example against any external AGT engine, this repository takes no
dependency on one, and nothing here calls one. Field names on the AGT side may
drift from whatever an engine currently accepts; the *semantic* mapping in the
table below is the durable part.

> **UNCERTIFIED — synthetic demo rule pack.** Every decision referenced here is
> produced by a **synthetic demo rule pack** — **not a fatwa / not certified /
> not production advice**. Its envelopes are **committee-reviewable demo
> evidence**. Scenario labels are generic synthetic placeholders ("casino-hotel",
> "mixed-revenue ETF", "subscription"). A certified version *would* carry
> standard citations and a scholar signature over the rule pack's hash; the
> demo carries an explicit `uncertified` slot instead.

## Why this mapping exists

AGT-class toolkits govern agents with *engineering* primitives: per-task
budgets, kill switches, scoped permissions, anomaly detection. They are policy
**engines**. What they do not ship is regulated compliance **content** — a
versioned, hashed, citation-bearing rule pack whose every decision is signed
and independently re-derivable.

These layers compose rather than compete. An AGT-style deployment that needs
payment-compliance decisions can keep its own engine for operational guardrails
and **delegate the compliance question to this authorizer**, consuming the
signed decision under the always-200 machine contract
([`docs/machine-contract.md`](./machine-contract.md)). This page defines that
seam precisely; the YAML in
[`examples/agt-example.governance.yaml`](../examples/agt-example.governance.yaml)
is one worked example of it.

## Concept mapping (normative side: this engine)

| This engine | `governance.toolkit/v1` projection | Notes |
|---|---|---|
| `POST /authorize` (payment intent in, signed decision out) | an external authorizer `check` inside a policy | The AGT engine remains the enforcement point; this service is the decision oracle it consults. |
| `decision: "allow"` | effect `permit` | Proceed; retain the evidence artifact in the audit log. |
| `decision: "deny"` | effect `block`, terminal | **Halt, no retry**: the evaluator is deterministic (no LLM, no clock, no randomness), so resubmitting the same intent re-derives the same deny. |
| `decision: "review"` | effect `escalate` (human-approval gate) | Not a soft permit and not a soft block — a human takes over. |
| HTTP 4xx `application/problem+json` | an **engine error**, never a policy outcome | error ≠ deny: no decision was made, nothing was signed. The AGT side must surface it as an integration fault and must not record a `block`. |
| `reason_codes` (closed set: `MAYSIR`, `INTOXICANTS`, `RIBA`, `GHARAR`, `MIXED_REVENUE`) | machine-readable violation codes on the outcome | Stable, enumerable, deterministic per intent + pack hash. |
| `matched_rules[]` | rule-level evidence detail | Carries title, description, and the `standards_ref` slot (`pending — populated on v1.0 certification`). |
| rule pack (`rule_pack_id`, `rule_pack_version`, `rule_pack_hash`) | policy-pack metadata + content address | The pack is git-tracked, RFC 8785-canonicalized, and content-addressed by its SHA-256; `GET /rule-packs/:id/:version` serves the exact canonical bytes. |
| `rule_pack_status: "uncertified"` | a required metadata label | The honesty marker is machine-readable on every response; it must survive the projection. |
| `evidence_artifact` (Ed25519 JWS-compact over the RFC 8785 canonical envelope) | the audit-evidence attachment | Verifiable offline with `verifier/verify.mjs` (zero server trust) and re-derivable with `npm run replay` — see [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md). |
| `scholar_signature_ref` (explicit `uncertified` specimen at v0.1) | attestation slot in pack metadata | A certified version *would* populate it with the scholar's `did:key` and a detached JWS over `rule_pack_hash`; v0.1 deliberately ships the labeled empty slot, never a bare null. |

## What does NOT map

- **No decision logic moves into the AGT document.** The YAML never restates
  the rules; it only points at the pack by id/version/hash. Re-encoding rules
  in a second engine would create two sources of truth and break the
  replay-key guarantee (`rule_pack_hash` + `evaluator_version` + `intent_hash`).
- **No LLM enters the decision path** on either side of the seam. The
  authorizer's determinism is the property the audit trail rests on.
- **Status-code semantics do not bend to the host engine.** Even when wrapped,
  a deny stays HTTP 200 + a signed envelope, and a 4xx stays an unsigned
  integration failure. An adapter that "helpfully" converts 4xx into `block`
  violates this contract.

## The worked example

[`examples/agt-example.governance.yaml`](../examples/agt-example.governance.yaml)
projects exactly the three generic demo scenarios onto the shape above:

| Scenario (generic label) | Real engine decision | Projected effect |
|---|---|---|
| agent books a casino-hotel | `deny`, `reason_codes: ["MAYSIR"]` | `block` (terminal, no retry) |
| agent rebalances a mixed-revenue ETF | `review`, `reason_codes: ["MIXED_REVENUE"]` | `escalate` (human approval) |
| agent sets up a subscription | `allow`, `reason_codes: []` | `permit` |

The decisions and the `rule_pack_hash`
(`5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4`) in the
YAML were captured from a running instance of this service — that half is
execution-verified. The **AGT-side field names are not** (see the label at the
top): treat the YAML as a schema-mapped illustration to adapt, not a document
known to load into any particular engine release.

## See also

- [`docs/machine-contract.md`](./machine-contract.md) — the always-200 /
  problem+json contract the adapter must preserve.
- [`docs/evaluator-semantics.md`](./evaluator-semantics.md) — the pinned
  evaluator semantics behind `deny = halt-no-retry`.
- [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) — how any third party verifies
  and replays the evidence the projection attaches.
