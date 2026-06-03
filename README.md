# compliance-authorizer

Runtime compliance authorization for agentic payments. A small, MIT-licensed service that
takes an AI agent's **payment intent** and returns a cited, tamper-evident
**allow / deny / review** decision with a cryptographic evidence envelope — driven by
versioned, hashed rule packs. The first rule pack is an **uncertified synthetic Shariah
profile (v0.1)**.

> **UNCERTIFIED — synthetic demo rule pack.** Not a fatwa. Not certified. Not production
> advice. Decisions here are illustrative; a certified version's standard citation and
> scholar signature populate on certification.

## What it is (and isn't)

- A runtime authorization API (`POST /authorize` → a signed decision envelope), a
  standalone **offline verifier** (trust nothing on the server), and a web playground +
  evidence viewer.
- Decision **provenance** — a signed allow/deny/review record. **Not** PII redaction.
- **Deterministic** — no LLM in the decision path; the same intent + rule-pack hash always
  yields the same decision.

## Status

Pre-implementation. The locked design layer is in [`DESIGN.md`](./DESIGN.md); the plan,
architecture decisions, and test contract live in the project's gstack artifacts. Read
`DESIGN.md` before building.

## License

MIT © 2026 Nouaïm Souiki
