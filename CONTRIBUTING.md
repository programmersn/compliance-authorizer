# Contributing to compliance-authorizer

This document walks you through setting up a local development environment, running the
tests, and understanding the conventions you need to follow.

> **UNCERTIFIED.** This service ships a synthetic demo rule pack -- not a fatwa, not
> certified, not production advice. All scenario labels are generic synthetic placeholders.

## Prerequisites

- **Node.js 22.6 or later** (`node --version` to check). The project uses native
  `--experimental-strip-types` to run TypeScript without a separate build step in dev.
- **npm** (bundled with Node.js).
- A Unix-like shell or Git Bash on Windows.

## Getting started

```sh
git clone https://github.com/programmersn/compliance-authorizer.git
cd compliance-authorizer
npm ci
```

`npm ci` installs exact locked versions from `package-lock.json`. Never use `npm install`
unless you are intentionally changing a dependency.

## Running the server

```sh
npm run dev
```

The server starts on `http://127.0.0.1:8787` by default. On first boot it generates a
fresh Ed25519 signing key under `.keys/issuer.jwk.json` (gitignored). Boot logs include
the active `rule_pack_hash` and `issuer_kid` -- keep these for verifying evidence
artifacts.

```
{"level":"info", ..., "rule_pack":"shariah@0.1.1", "issuer_kid":"...", "msg":"compliance-authorizer up"}
```

To change the port or key directory, set `PORT` or `KEYS_DIR` before starting (see
[Configuration](./README.md#configuration)).

## Running the test suite

```sh
npm test            # all 393 tests (26 files)
npm run typecheck   # TypeScript compiler check (no emit)
npm run lint        # ESLint
```

CI runs `typecheck → lint → test` in that order on every push and pull request. Your PR
must pass all three. The test suite covers:

- **Crypto** -- Ed25519 sign/verify, JWS canonicalization, property-based agreement
  between the service canonicalizer and the independent verifier (seeded fast-check),
  negative-alg JOSE cases (alg:none, HS256 substitution, tampered payload/signature,
  unknown kid).
- **HTTP routes** -- `POST /authorize`, `GET /.well-known/jwks.json`,
  `GET /rule-packs/:id/:version`, `POST /verify`.
- **Rule evaluator** -- operator semantics, field resolution, conflict resolution.
- **Replay CLI** -- `scripts/replay.ts`, including `--jwks` combined verdict, exit-code
  contracts, and schema-gate behavior.
- **Offline verifier** -- `verifier/verify.mjs` envelope-schema checks, standalone
  round-trip.
- **End-to-end fixture** -- sign → offline-verify round-trip using the committed example.

## Project layout

```
src/
  crypto/         Ed25519 keys, JWS compact, RFC 8785 canonicalization
  evidence/       Evidence envelope builder + replay logic
  http/           RFC 9457 problem+json helpers
  routes/         Fastify route handlers (authorize, jwks, rule-packs, verify)
  rules/          Deterministic evaluator + rule-pack loader + TypeBox schema
  index.ts        Server entry point (dev/demo boot)
  server.ts       Fastify app factory (used by tests and index.ts)
verifier/
  verify.mjs      Standalone offline verifier (node built-ins only, zero server trust)
scripts/
  replay.ts       Decision-replay CLI
  build-example.ts Regenerates examples/ deterministically
rule-packs/
  shariah/0.1.1.json  Synthetic Shariah v0.1 rule pack (UNCERTIFIED)
docs/
  evaluator-semantics.md  Pinned evaluator contract for D12 replayability
  getting-started.md      Tutorial: zero to first signed decision
examples/               Committed, byte-reproducible worked example
test/                   Vitest test files mirroring src/ layout
```

## Code conventions

- **All English** -- identifiers, filenames, and comments must use English. French UI labels
  that appear in test scenarios may be noted in comments but the identifier itself must be
  English.
- **No LLM in the decision path** -- the evaluator is pure and deterministic. If you touch
  `src/rules/evaluator.ts` or `src/rules/loader.ts`, you must bump `EVALUATOR_VERSION` in
  `evaluator.ts` and update `docs/evaluator-semantics.md` to match.
- **error ≠ deny** -- a decision (allow/deny/review) is always HTTP 200 with a signed
  envelope. An integration failure (malformed input, unknown profile, server error) is a
  4xx/5xx RFC 9457 problem+json response with **no** signed envelope. Never conflate the
  two.
- **UNCERTIFIED on every surface** -- any rendered decision must carry the UNCERTIFIED
  marker in amber/ochre, never red. Honesty wording is verbatim in `CLAUDE.md`.
- **Synthetic data only** -- no PII, no real card or customer data anywhere in the repo.
- **Minimal dependencies** -- check `CLAUDE.md` before adding a new dependency.

## Crypto surface

The crypto and canonicalization modules (`src/crypto/`) are the crown-jewel surface.
Changes there require:

1. Property-based tests confirming agreement between `src/crypto/canonicalize.ts` and
   `verifier/verify.mjs` (they must agree on every input, including inputs they reject).
2. Negative-alg tests -- `alg:none`, algorithm substitution, tampered payload, tampered
   signature must all be rejected before key material is touched.
3. If you change the JWS structure or the canonicalization contract, update
   `verifier/verify.mjs` in lockstep -- the offline verifier is independently importable
   and must stay consistent with the service's `src/crypto/jws.ts`.

## Submitting a pull request

1. Create a branch off `main` (any name).
2. Make your changes; run `npm test && npm run typecheck && npm run lint`.
3. Push and open a PR against `main`.
4. The repo enforces **squash-only merges** -- your commits will be squashed into one.
   Write a good PR description; the commit message is generated from it at merge time.
5. Merge with `gh pr merge <n> --squash --delete-branch`.

## Verifying and replaying evidence

Two tools let you check decisions produced by the server without trusting it:

```sh
npm run verify:fixture   # offline authenticity check on the committed example
npm run replay           # reproducibility check (re-derives the decision)
npm run replay:verified  # both: reproduced AND authentic, single exit code
```

See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for the full zero-trust walkthrough
and [`examples/README.md`](./examples/README.md) for what each committed file is.
