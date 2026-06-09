# Changelog

All notable changes to this project are documented in this file.
Versions follow a 4-digit MAJOR.MINOR.PATCH.MICRO scheme; dates are YYYY-MM-DD.

## [0.2.0.0] - 2026-06-09

### Added

- `GET /.well-known/jwks.json` (RFC 7517): publishes every historical public verifying key,
  so any envelope ever signed by this engine stays offline-verifiable by `kid` across key
  rotation. Public keys only — the private `d` never reaches the wire.
- `GET /rule-packs/:id/:version`: serves the exact canonical rule-pack bytes a given envelope
  was decided against; `sha256` of the response body round-trips to the envelope's
  `rule_pack_hash`. A miss is RFC 9457 problem+json (404), never a decision artifact.
- `POST /verify`: submit an evidence artifact and get a verification verdict. A well-formed
  request is ALWAYS HTTP 200 — `valid:false` (inauthentic artifact) is a verdict, never a 4xx;
  a malformed request is 400 problem+json with no verdict (error ≠ deny on the verification
  path too). Reuses the standalone offline verifier, so the server surface and the offline
  path can never disagree on a verdict.
- Reproducible-decision replay (`scripts/replay.ts`) keyed on `rule_pack_hash` +
  `evaluator_version` + `intent_hash`, plus `REPRODUCIBILITY.md` and self-contained
  `examples/` (artifact, JWKS, pack) that round-trip through the offline verifier.

### Security

- JWS signature-segment malleability closed on BOTH independent verifiers
  (`verifier/verify.mjs` and `src/crypto/jws.ts`): each base64url segment must be canonical
  and unpadded (decode/re-encode round-trip equality), and the signature must decode to exactly
  64 bytes. A byte-different re-encoding of a valid artifact (trailing `=` padding, a
  non-canonical final character) no longer verifies as valid evidence — one decision has
  exactly one valid artifact string.
- JWKS publish boundary hardened: `assertPublishableJwk` rejects any published key whose `x`
  is not an importable Ed25519 point (not merely thumbprint-consistent); `buildJwks` projects
  every key to its six public members so the no-private-`d` guarantee holds at the data layer,
  not only at the response schema; the published key set is snapshotted and frozen at boot, so
  a post-boot mutation cannot change what JWKS and `/verify` serve.
- Boot guard: the live signing key must be among the published keys, or the engine refuses to
  boot — its decisions would otherwise fail its own JWKS and `/verify`.
- `POST /verify` reports `issuer: null` on an inauthentic artifact, never surfacing a
  claimed-but-unverified identity (mirrors the offline CLI).

### Fixed

- Offline decision replay (`scripts/replay.ts`) now classifies an artifact whose cited pack pins a
  different `evaluator_version` as a reproducibility verdict (`reproduced:null`, "replay could not be
  attempted", exit 1) instead of an operator/input error (exit 2). The loader's D12 evaluator-version
  assertion is now opt-out, so the replay tool validates and hashes a foreign-evaluator pack and lets
  `replayEnvelope` classify it; the `rule_pack_hash` content guard is unchanged, so a wrong or
  tampered pack is still rejected.

### Notes

- The UNCERTIFIED marker remains unavoidable on every served surface: synthetic demo rule pack
  — not a fatwa, not certified, not production advice. No LLM in the decision path.

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
