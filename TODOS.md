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
All W2 deliverables shipped in **v0.2.0.0 (2026-06-09)** — see Completed.

### Deferred hardening (from the v0.2.0.0 cross-vendor review)
- [ ] Verifier-side strict envelope schema in `verifier/verify.mjs` — reject unknown fields and
      enforce types/formats (`envelope_version`, `reason_codes`/`matched_rules` array shapes,
      `rule_pack_hash` + timestamp formats), not just required-field presence. A signed-but-malformed
      envelope is only producible by the key holder, so this is robustness, not an outsider-reachable
      hole. **Priority:** P2
- [ ] `scripts/replay.ts` exit-code semantics — replay decodes the payload and re-evaluates WITHOUT
      checking authenticity (by design, and loudly labelled). Consider a distinct non-zero status
      (or requiring `--jwks` + a verify pass) so automation consuming only the exit code cannot
      confuse "payload re-derived" with "valid evidence re-derived." **Priority:** P3
- [ ] RFC 8785 lone-surrogate handling — both canonicalizers (`src/crypto/canonicalize.ts` and
      `verifier/verify.mjs`) serialize strings via `JSON.stringify`, which ESCAPES lone surrogates
      (ES2019 well-formed stringify) rather than rejecting them. Verify whether strict RFC 8785
      requires invalid-Unicode input to FAIL; if so, reject lone surrogates at the canonicalization
      boundary (or validate intent strings at `/authorize`). Both verifiers AGREE today (not a
      forgery); the only risk is that a strict external JCS verifier could reject a signed artifact
      carrying a lone surrogate. Pre-existing (W1 `canonicalize.ts`, unchanged by W2); surfaced by the
      v0.2.0.0 cross-vendor review — candidate for `/deep-research` on the RFC requirement. **Priority:** P3

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
- [x] always-200 verification contract + `GET /.well-known/jwks.json` (all historical keys) +
      `GET /rule-packs/:id/:version` + `POST /verify` (server surface reuses the offline verifier;
      `valid:false` is a 200 verdict, malformed is 400 problem+json)
      **Completed:** v0.2.0.0 (2026-06-09)
- [x] Reproducible-decision replay (rule_pack_hash + evaluator_version + intent_hash) +
      `REPRODUCIBILITY.md` + self-contained `examples/`
      **Completed:** v0.2.0.0 (2026-06-09)
- [x] JWS signature-segment malleability closed + JWKS publish-boundary / boot-guard hardening
      (both verifiers reject non-canonical base64url + non-64-byte signatures; importable-key,
      live-signer-in-set, and frozen published-set boot guards; `issuer:null` on inauthentic)
      **Completed:** v0.2.0.0 (2026-06-09)
- [x] `POST /authorize` → Ed25519 JWS-compact signed evidence envelope
      **Completed:** v0.1.0.0 (2026-06-05)
- [x] Standalone offline verifier (zero server trust)
      **Completed:** v0.1.0.0 (2026-06-05)
- [x] One minimal Shariah v0.1 rule pack + one test fixture
      **Completed:** v0.1.0.0 (2026-06-05)
