# TODOS — compliance-authorizer build

Build tasks for the W1-W4 prototype — **build scope only**. Design spec: [`DESIGN.md`](./DESIGN.md).
Strategy, outreach, and research planning live in the project's private workspace, not here;
the `T-D*` task IDs trace to the private planning records.

## W1 — crypto/API core (the gate; build synchronously)
- [ ] **GATE:** sign → offline-verify round-trip green in CI; property-based + negative-alg
      tests (alg:none, alg-substitution, tampered payload/sig all rejected) + canonicalization invariance
      — *test matrix complete and green locally (106/106 at v0.1.0.0, 2026-06-05); tick only when the
      `w1-gate` workflow has actually run green on GitHub (Actions billing-locked at ship time)*
      **Priority:** P0
- [ ] **Deferred cross-vendor review (Codex):** re-run the outside-voice pass skipped in the
      2026-06-05 review (tool quota; earliest re-run 2026-07-02). Scope: the W1 crypto/API core
      diffed against pre-W1 base `0b2b4d2` — `src/crypto/`, `src/evidence/`, `src/rules/`,
      `src/http/`, `src/routes/`, `src/server.ts`, `src/index.ts`, `verifier/verify.mjs`,
      `rule-packs/shariah/0.1.0.json`, `test/` (exclude `package-lock.json`). Both passes:
      adversarial (`codex exec`, read-only, high reasoning) + structured (`codex review`);
      triage any findings through the standard fix-first flow before W3-4 ships.
      **Pinned at /ship (2026-06-05): upper bound `2985539`** — the last W1 code commit
      (later commits in the W1 PR touch only docs/VERSION/CHANGELOG, which the scope above
      excludes). W2 modifies the same files, so an open-ended `git diff 0b2b4d2` would mix
      W1+W2 scopes; review exactly `git diff 0b2b4d2..2985539` minus `package-lock.json`.
      **Priority:** P1

## W2 — backend completion
- [ ] always-200 decision contract (deny = 200, read the body) + RFC 9457 4xx for integration failures
- [ ] `GET /.well-known/jwks.json` (all historical keys) · `GET /rule-packs/:id/:version` · `POST /verify`
- [ ] Reproducible-decision replay (rule_pack_hash + evaluator_version + intent_hash)
- [ ] `REPRODUCIBILITY.md` + self-contained `examples/`

## W3-4 — web surfaces (build to DESIGN.md + design/ mockups)
- [ ] T-D1 evidence viewer (match `design/evidence-viewer-chosen.html`)
- [ ] T-D2 playground + all six interaction states (include a REVIEW scenario)
- [ ] T-D3 landing (match `design/landing-mockup.html`)
- [ ] T-D4 design tokens + IBM Plex (verify WCAG AA)
- [ ] T-D5 scholar-attestation SVG + Mermaid system/data-flow diagrams
- [ ] T-D6 print stylesheet + a11y baseline
- [ ] T-D7 3-min demo-video storyboard
- [ ] T-D8 copy-guard pass (honesty wording; generic public labels)

## Guards (every task)
Synthetic data only · no LLM in the decision path · error ≠ deny · UNCERTIFIED unavoidable +
amber (never red) · generic public labels only (no named institutions) · honesty wording verbatim ·
forward-projection copy stays future-conditional.

## Completed
- [x] `POST /authorize` → Ed25519 JWS-compact signed evidence envelope
      **Completed:** v0.1.0.0 (2026-06-05)
- [x] Standalone offline verifier (zero server trust)
      **Completed:** v0.1.0.0 (2026-06-05)
- [x] One minimal Shariah v0.1 rule pack + one test fixture
      **Completed:** v0.1.0.0 (2026-06-05)
