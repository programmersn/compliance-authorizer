# compliance-authorizer — project instructions

Runtime compliance authorization for agentic payments. An MIT-licensed service: an AI agent's
payment intent in → a signed **allow / deny / review** decision + cryptographic evidence envelope
out, driven by versioned rule packs. The first pack is an uncertified synthetic Shariah profile
(v0.1). Build spec: `DESIGN.md`. Task list: `TODO.md`.

## Architecture (locked — do not relitigate)
- TypeScript / Node + Fastify + TypeBox (OpenAPI auto-generated from TypeBox).
- Crypto: Ed25519 + JWS-compact + JCS canonicalization (RFC 8785); did:key for scholar signatures.
- Persistence: SQLite (`node:sqlite`, better-sqlite3 fallback). Rule packs are git-tracked.
- A standalone **offline verifier** is the truly-independent verification path.
- **Deterministic — NO LLM in the decision path.** Same intent + rule_pack_hash → same decision.

## Non-negotiable guards
- **error ≠ deny.** A decision (allow/deny/review) → HTTP **200** + a SIGNED envelope. An
  integration failure → RFC 9457 problem+json **4xx** (400/422/404), NEVER a signed envelope.
  In the UI a failure is a distinct error panel, never a decision certificate.
- **UNCERTIFIED is unavoidable** on any rendered decision; amber/ochre, **never red**.
- **Honesty wording (verbatim):** "synthetic demo rule pack", "not a fatwa / not certified /
  not production advice", "committee-reviewable demo evidence" (never "board-readable").
- **Public-content discipline:** NO named real institutions or individuals anywhere public —
  scenario labels stay generic ("casino-hotel", "mixed-revenue ETF", "subscription").
- **Forward-projection copy stays future-conditional** ("a certified version *would*…", never "does").

## Conventions
- All code identifiers, filenames, and comments in **English**.
- **Synthetic data only** — no PII, no real card/customer data.
- Minimal dependencies; agentic-coded HTML/CSS for the web surfaces (no bespoke design pipeline).
- Crypto / canonicalization is the crown-jewel surface: property-based + negative-alg tests are mandatory.

## Build sequence
W1 crypto/API core (the CI gate) → W2 backend → W3-4 web surfaces (to `DESIGN.md` + `design/`).
See `TODO.md`. Build W1 carefully and synchronously; the gate is the sign → offline-verify round-trip.
