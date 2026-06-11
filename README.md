# compliance-authorizer

Runtime compliance authorization for agentic payments. A small, MIT-licensed service that
takes an AI agent's **payment intent** and returns a cited, tamper-evident
**allow / deny / review** decision with a cryptographic evidence envelope — driven by
versioned, hashed rule packs. The first rule pack is an **uncertified synthetic Shariah
profile (v0.1)**.

> **UNCERTIFIED — synthetic demo rule pack.** Not a fatwa. Not certified. Not production
> advice. Decisions here are illustrative; a certified version would carry standard
> citations and a scholar signature over the rule pack's hash.

## What it is (and isn't)

- A runtime authorization API (`POST /authorize` → a signed decision envelope),
  verification endpoints (`GET /.well-known/jwks.json`, `GET /rule-packs/:id/:version`,
  `POST /verify`), a standalone **offline verifier** and decision **replay** tool, and a
  web playground + evidence viewer (W3-4, not built yet).
- Decision **provenance** — a signed allow/deny/review record. **Not** PII redaction.
- **Deterministic** — no LLM in the decision path; the same intent + rule-pack hash always
  yields the same decision.
- The **UNCERTIFIED marker lives on both surfaces, under different names**: the HTTP
  response mirrors it as top-level `rule_pack_status` (readable without decoding
  anything); inside the signed envelope — the durable artifact — it is carried at
  `scholar_signature_ref.status`. The envelope is the canonical record; the response
  field is a convenience mirror.

## Status

**W1 — crypto/API core: complete (v0.1.0.0).** `POST /authorize` issues Ed25519-signed
evidence envelopes (JWS-compact over RFC 8785 canonical JSON); the standalone offline
verifier (`verifier/verify.mjs`, node built-ins only) checks them with zero server trust;
the uncertified synthetic Shariah v0.1 pack and the crypto test matrix (negative-alg,
property-based, canonicalization invariance) are in.

**W2 — backend: complete (v0.2.1.0).** `GET /.well-known/jwks.json` publishes all
historical verifying keys (RFC 7517) so any envelope stays offline-verifiable across key
rotation. `GET /rule-packs/:id/:version` serves the exact canonical pack bytes a decision
was made against (sha256 of the response body equals the envelope's `rule_pack_hash`).
`POST /verify` accepts an evidence artifact; a **well-formed** request always returns HTTP 200
with two distinct verdict fields: `valid` (authenticity — was this signed by the issuer's key,
intact and canonical?) and `reproducibility` (does the cited decision re-derive against the cited
pack?). `valid:false` is a verdict, not a 4xx. A malformed request (missing field, wrong type,
extra field) returns 400 problem+json — error ≠ deny on the verification path too. Decision replay (`scripts/replay.ts`) re-derives the decision from the cited intent
and pack; `--jwks` adds an authenticity gate so a single exit code covers both properties.
The verifier enforces the EXACT v0.1 envelope schema and rejects RFC 8785 lone surrogates
on both canonicalizers. `npm test` covers 218 tests across 14 test files. See
[`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for the zero-trust walkthrough and
[`examples/`](./examples/) for a committed, byte-reproducible worked example.

The web surfaces (W3-4: playground, evidence viewer) are not built yet. The locked design
layer is in [`DESIGN.md`](./DESIGN.md) and the build tasks are in [`TODOS.md`](./TODOS.md).
Read `DESIGN.md` before building.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port the service listens on. Must be an integer in `[1, 65535]`. |
| `KEYS_DIR` | `.keys/` | Directory where the Ed25519 signing key is stored (gitignored). Created and populated automatically on first boot. |

## License

MIT © 2026 Nouaïm Souiki
