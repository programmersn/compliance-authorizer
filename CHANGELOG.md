# Changelog

All notable changes to this project are documented in this file.
Versions follow a 4-digit MAJOR.MINOR.PATCH.MICRO scheme; dates are YYYY-MM-DD.

## [0.1.0.0] - 2026-06-05

### Added

- `POST /authorize`: submit a synthetic payment intent and get an allow / deny / review
  decision with a signed evidence envelope (Ed25519, JWS-compact over RFC 8785 canonical
  JSON). A decision — including deny — is always HTTP 200; integration failures return
  RFC 9457 problem+json and never carry an evidence envelope (error ≠ deny).
- Standalone offline verifier (`verifier/verify.mjs`, Node built-ins only): verify any
  evidence artifact with zero trust in the issuing server — structure, pinned algorithm,
  key resolution by RFC 7638 thumbprint, signature, canonical form, intent hash, and
  rule-pack consistency including the pinned evaluator version. Prints the issuer's
  did:key fingerprint with a trust-anchor note for out-of-band comparison.
- Uncertified synthetic Shariah v0.1 rule pack — 8 deterministic rules over generic demo
  scenarios (casino-hotel, mixed-revenue ETF, subscription) with hash-committed,
  data-driven decision precedence. The UNCERTIFIED marker is unavoidable on every
  surface: synthetic demo rule pack — not a fatwa, not certified, not production advice.
- Deterministic rule evaluator pinned by `evaluator_version` (semantics contract in
  `docs/evaluator-semantics.md`): same intent + same rule-pack hash always yields the
  same decision; no LLM in the decision path.
- Crypto test matrix (106 tests): property-based agreement between the service's
  canonicalizer and the independent verifier reimplementation (seeded fast-check),
  negative-alg JOSE cases (alg:none, HS256 substitution, tampered payload and
  signature, unknown kid), and the end-to-end sign → offline-verify gate fixture run
  against the real verifier as a child process.
- Dev boot hardening: guarded startup with actionable operator messages, atomic
  issuer-key writes (temp + rename), and strict PORT validation.
