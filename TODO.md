# TODO — compliance-authorizer build

Build tasks for the W1-W4 prototype. Design spec: [`DESIGN.md`](./DESIGN.md). Strategy,
outreach, and research planning live in the private project vault, not here.

## W1 — crypto/API core (the gate; build synchronously)
- [ ] `POST /authorize` → Ed25519 JWS-compact signed evidence envelope
- [ ] Standalone offline verifier (zero server trust)
- [ ] One minimal Shariah v0.1 rule pack + one test fixture
- [ ] **GATE:** sign → offline-verify round-trip green in CI; property-based + negative-alg
      tests (alg:none, alg-substitution, tampered payload/sig all rejected) + canonicalization invariance

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
