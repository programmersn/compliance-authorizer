# TODOS — compliance-authorizer build

Build tasks for the W1-W4 prototype — **build scope only**. Design spec: [`DESIGN.md`](./DESIGN.md).
Strategy, outreach, and research planning live in the project's private workspace, not here;
the `T-D*` task IDs trace to the private planning records.

## W1 — crypto/API core (the gate; build synchronously)
- [x] **GATE:** sign → offline-verify round-trip green in CI; property-based + negative-alg
      tests (alg:none, alg-substitution, tampered payload/sig all rejected) + canonicalization invariance
      — **green in CI 2026-06-08** on PR #1 head `f346a5f` (run 27136075954: npm ci → typecheck →
      lint → test, all ✓), after the GitHub Actions billing lock was cleared. **Priority:** P0
- [x] **Deferred cross-vendor review (Codex):** **completed 2026-06-08** — both passes ran on
      the pinned range `git diff 0b2b4d2..2985539` minus `package-lock.json` (adversarial
      `codex exec` + structured `codex review`, high reasoning). Both passes independently
      flagged ONE divergence as the top finding: `verifyCompact` did not bind `kid` to the
      RFC 7638 thumbprint (the offline verifier already did). Triaged 5 findings; 2 real ones
      fixed + regression-tested in `f346a5f` (kid-thumbprint parity in `verifyCompact`;
      `importPrivateJwk` x/d consistency). Others assessed already-mitigated / not-reachable /
      W2-scope (documented in the commit + the review log). **Priority:** P1

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
