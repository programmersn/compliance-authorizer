# Changelog

All notable changes to this project are documented in this file.
Versions follow a 4-digit MAJOR.MINOR.PATCH.MICRO scheme; dates are YYYY-MM-DD.

## [0.2.1.0] - 2026-06-10

Deferred hardening from the v0.2.0.0 cross-vendor review. The three schema/canonicalization
items are key-holder-only robustness (a signed-but-malformed artifact is only producible by the
issuer, not an outsider-reachable hole), cleared before the W3 web surfaces so the viewer renders
against a strict, RFC-defensible verifier contract. A pre-merge cross-model review of this work
then surfaced a parity gap on the offline replay CLI (operator-facing, not key-holder-only): it
did not enforce that same strict schema and mis-typed exit codes on operator errors. The Fixed
section below closes it so the two verification tools (verify and replay) reject the identical
malformed artifacts and both keep error ≠ verdict.

### Security

- Strict evidence-envelope schema in the offline verifier (`verifier/verify.mjs`): the
  envelope-shape check now enforces the EXACT v0.1 schema — the precise field set (unknown
  fields are rejected), `envelope_version` pinned to `0.1.0`, and every field's type and format
  (sha256-hex hashes, semver versions, `ev-<uuid>` decision id, `Date.toISOString` timestamp,
  `reason_codes`/`matched_rules` array shapes, the UNCERTIFIED `scholar_signature_ref` shape) —
  not merely required-field presence. `POST /verify` inherits it (it reuses the same
  `verifyEvidence`), so the served and offline verdicts stay identical.
- RFC 8785 §3.2.2.2 lone-surrogate rejection on BOTH canonicalizers
  (`src/crypto/canonicalize.ts` and `verifier/verify.mjs`): invalid Unicode (an unpaired UTF-16
  surrogate) now terminates canonicalization with an error instead of being silently escaped as
  `\udXXX` by ES2019 well-formed `JSON.stringify`. That escaping is a non-compliant code path
  the RFC's own rationale flags ("interoperability issues including broken signatures") and that
  the RFC author's Go reference and strict verifiers (`gowebpki/jcs`, `json-canon`) reject — so
  an escaped-surrogate artifact would have failed to verify elsewhere. At `POST /authorize` an
  intent carrying a lone surrogate is now a 400 problem+json (malformed request), never a signed
  envelope (error ≠ deny). The two canonicalizers are property-tested to agree on every input,
  including which inputs they reject.

### Added

- `scripts/replay.ts` optional `--jwks` combined verdict (and `npm run replay:verified`). By
  default replay stays reproducibility-only and exit 0 is loudly labelled "authenticity NOT
  checked"; with `--jwks` it also runs the independent verifier and requires reproduced AND
  authentic for exit 0 (exit 1 if either fails). This closes a conflation where automation
  reading only the exit code could mistake a bare "decision re-derived" for "valid evidence,"
  while preserving the two-tools/two-properties separation — the default path still never touches
  the signature. In `--jwks` mode authenticity is settled BEFORE the pack-mismatch operator-error
  path: a FORGED artifact (e.g. a tampered `rule_pack_hash`, which breaks the signature) is an
  authenticity FAIL (exit 1), never misreported as an exit-2 "supply the cited pack" operator
  error; an authentic artifact for which the operator supplied the wrong `--pack` still exits 2.
  A non-canonicalizable (lone-surrogate) envelope is rejected uniformly as a malformed artifact
  (exit 2) on every branch, including the D12 evaluator-mismatch path.

### Fixed

- The offline replay CLI (`scripts/replay.ts`) now enforces the strict v0.1 envelope schema
  before re-evaluation, reusing the verifier's own `validateEnvelopeShape` (the exact check
  `POST /verify` runs) as the single source of truth — so the two verification tools reject the
  identical malformed artifacts. Bare replay previously had NO schema gate: a structurally-valid
  envelope missing a required field could crash the tool with an uncaught canonicalization error
  (Node exit 1, the verdict code) or, worse, emit a false `REPRODUCED` (exit 0) to automation
  reading only the exit code. Both are now a clean operator error (exit 2, "nothing was
  replayed"). A defensive guard also wraps the re-evaluation so a canonicalization failure can
  never resurface as an uncaught exit-1 stack — mirroring the verifier's "a crash is never a
  verdict" discipline.
- Bad CLI usage — an unknown flag, a stray positional, or a value-option given with no value —
  now exits 2 (operator error) in BOTH `scripts/replay.ts` and `verifier/verify.mjs`. Previously
  `parseArgs` threw before the input guard, so Node exited 1 (the "not valid evidence / not
  reproduced" verdict code) on a mere typo, which automation chaining the tools would misread.
- `scripts/replay.ts` now rejects a non-canonical base64url JWS segment (e.g. one carrying `=`
  padding) as malformed input (exit 2), matching the offline verifier; bare replay previously
  accepted the lenient encoding and could report `REPRODUCED` for a non-compact JWS.

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
- Both verifiers (`verifier/verify.mjs` and `src/crypto/jws.ts`) now snapshot the matched JWKS key with
  a single read per field AND bind the snapshot `kid` to the protected-header `kid` (already matched at
  lookup), rather than re-reading the entry's `x`/`kid`. The verifiers read the key's `x` and `kid` more
  than once (lookup, thumbprint, did:key, signature), so a hostile in-process getter/Proxy could have
  presented honest values at the `kid`==thumbprint check and attacker values at signature verification
  — a property-read TOCTOU that let an artifact verify under a key whose `kid` disagreed with the one it
  claims. Not reachable through the route or CLI (both pass plain JSON), but the verifiers are
  independently importable, so both are brought to parity. Regression-tested (x-flip and kid-flip) on
  both.
- `src/crypto/jws.ts` `verifyCompact` now tolerates a malformed (null / non-object) JWKS entry the same
  way the offline verifier does — skipping it and returning a `kid_unknown` `JwsError` rather than a raw
  `TypeError` — honoring its "JwsError on any defect" contract and keeping the two verifiers in lockstep.
- `verifier/verify.mjs` now populates the returned `issuer` only AFTER the Ed25519 signature verifies,
  so the exported `verifyEvidence` never returns a non-null `issuer` alongside an invalid signature (it
  stays set when a later, non-signature check fails — the signer is genuine there). The `POST /verify`
  route already suppressed this; the fix closes it at the exported API and corrects the `verify.d.mts`
  type doc.
- The shared AJV validation problem renderer (`src/http/problem.ts`) is now request-body-agnostic
  ("Request body failed schema validation"), so a malformed `POST /verify` body no longer returns the
  `/authorize`-specific "not a valid payment intent" message. The per-field `issues` array is unchanged.

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
