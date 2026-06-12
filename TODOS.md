# TODOS — compliance-authorizer build

Build tasks for the W1-W4 prototype — **build scope only**. Design spec: [`DESIGN.md`](./DESIGN.md).
Strategy, outreach, and research planning live in the project's private workspace, not here;
the `T-D*`/`ET*`/`DT*` task IDs trace to the private planning records.

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

### Deferred hardening (from the v0.2.0.0 cross-vendor review) — all cleared in v0.2.1.0 (2026-06-11)
- [x] **P2 — Verifier-side strict envelope schema** (`verifier/verify.mjs`): the envelope-shape check
      now enforces the EXACT v0.1 schema — precise field set (unknown fields rejected),
      `envelope_version` pinned to `0.1.0`, and every field's type + format (sha256-hex hashes, semver,
      `ev-<uuid>` id, `Date.toISOString` timestamp, `reason_codes`/`matched_rules`/`scholar_signature_ref`
      shapes) — not just required-field presence. `POST /verify` inherits it via the shared
      `verifyEvidence`. Done **v0.2.1.0**; `test/verifier/envelope-schema.test.ts`.
- [x] **P3 — `scripts/replay.ts` exit-code semantics**: added an optional `--jwks` combined verdict
      (`npm run replay:verified`). Bare replay is unchanged (exit 0 = reproduced, loudly labelled
      "authenticity NOT checked"); with `--jwks`, exit 0 requires reproduced AND authentic (exit 1 if
      either fails). The default path still never checks the signature, so the two-tools/two-properties
      invariant holds. Done **v0.2.1.0**.
- [x] **P3 — RFC 8785 lone-surrogate handling**: `/deep-research` resolved the open RFC question —
      §3.2.2.2 NORMATIVELY requires terminating on invalid Unicode (a BCP-14 MUST whose stated rationale
      is "broken signatures"), and implementations DIVERGE (the RFC author's JS ref escapes, Java passes
      through, Go ref + strict verifiers reject), so escaping is a real interop hazard, not just a
      theoretical one. Both canonicalizers (`src/crypto/canonicalize.ts` + `verifier/verify.mjs`) now
      REJECT lone surrogates instead of ES2019-escaping them; `/authorize` maps the failure to 400
      problem+json (error ≠ deny). Property-tested to agree, including on rejection. Done **v0.2.1.0**
      (citation trail in `CHANGELOG.md`).

## W3-4 — web surfaces + backend completion remainder (boil the lake)
All W3-4 deliverables shipped in **v0.3.0.0 (2026-06-12)** — see Completed. The set: the
design surfaces (T-D1..T-D8), the eng-plan-parity remainder (ET16+ET17 agent credentials,
ET14 evidence store, ET18 AGT mapping, ET20 scholar-attestation path), and the DevEx docs
(DT1 machine contract, DT2 reason codes, DT8 `llms.txt`/`AGENTS.md`).

## Guards (every task)
Synthetic data only · no LLM in the decision path · error ≠ deny · UNCERTIFIED unavoidable +
amber (never red) · generic public labels only (no named institutions) · honesty wording verbatim ·
forward-projection copy stays future-conditional.

## Completed
- [x] Single-scroll web surface (T-D1..T-D4, T-D6): landing + playground + evidence viewer served
      same-origin from `web/` via `@fastify/static` (`GET /`), vanilla ES modules, no build step;
      all six interaction states (idle → loading → slow-copy swap → allow / deny / REVIEW
      certificate, plus the dashed problem-panel and network-error paths — error ≠ deny in the UI),
      DESIGN.md §4 design tokens (IBM Plex, WCAG AA), print stylesheet + a11y baseline. UNCERTIFIED
      amber chip + verbatim honesty wording on every rendered decision; a drift guard asserts every
      hardcoded pack/evaluator/hash and every absolute link answers 200.
      **Completed:** v0.3.0.0 (2026-06-12)
- [x] T-D5 / T-D7 / T-D8 design closeout: scholar-attestation SVG + system/data-flow diagrams,
      the 3-minute demo-video storyboard (`docs/demo-storyboard.md`), and the copy-guard pass
      (honesty wording verbatim, generic public labels only, forward-projection future-conditional).
      **Completed:** v0.3.0.0 (2026-06-12)
- [x] ET16 + ET17 agent-credential two-layer enforcement: `agent_credential` is an OPTIONAL
      payment-intent field; a presented synthetic signed `did:key` credential
      (`synthetic-agent-mcc-scope/0.1`, scope `{ allowed_mcc: [<4-digit>] }`) is verified, then its
      MCC scope ∩ the rule pack is enforced most-restrictive (evaluator bumped to 0.2.0, pack
      re-versioned `shariah@0.1.1`). A VALID credential whose scope excludes the intent's
      `merchant.mcc` → signed `deny` carrying the ONE new closed code `AGENT_SCOPE_EXCEEDED`; an
      invalid / tampered / alg-confused credential → 4xx problem+json, NEVER a signed deny
      (error ≠ deny). Offline replay parity proven. **Completed:** v0.3.0.0 (2026-06-12)
- [x] ET14 remainder — `node:sqlite` evidence store (better-sqlite3 fallback) wired on
      `POST /authorize`: signed envelopes persist (schema + round-trip + duplicate-rejection +
      fail-closed tested); the W2 routes shipped stateless. **Completed:** v0.3.0.0 (2026-06-12)
- [x] ET18 AGT mapping (`docs/agt-mapping.md`) + example governance YAML
      (`examples/agt-example.governance.yaml`), worded schema-mapped (not engine-verified).
      **Completed:** v0.3.0.0 (2026-06-12)
- [x] ET20 scholar-attestation path (`src/scholar/`): did:key detached JWS over `rule_pack_hash`
      + named-scholar metadata shape; v0.1 ships an UNCERTIFIED specimen
      (`examples/scholar-attestation.specimen.json`, fully synthetic labels), never a bare null.
      **Completed:** v0.3.0.0 (2026-06-12)
- [x] DevEx docs DT1 / DT2 / DT8: `docs/machine-contract.md` (the normative always-200 reference —
      a deny is HTTP 200, 4xx is never a signed decision), `docs/reason-codes.md` (closed
      reason-code reference + actionable problem+json), and `llms.txt` + `AGENTS.md` (agent-facing:
      reading a deny + reason_codes + halting). **Completed:** v0.3.0.0 (2026-06-12)
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
