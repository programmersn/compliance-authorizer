# DESIGN.md — Runtime Compliance Authorization (Shariah v0.1 prototype)

Locked by `/plan-design-review` (T-15) on 2026-06-03. This is the visual/IA/state
layer that sits ON TOP of the locked DX8 data contract, DX11 honesty wording, and eng
D1-D12. **Every W3-4 design surface calibrates against this file.** When agentic-coding
any surface, load this first; it exists so the build does not reinvent a generic look
each session.

Approved visual references (hand-built HTML — the literal build targets):
- Evidence viewer: `design/evidence-viewer-chosen.html`
- Landing: `design/landing-mockup.html`

---

## 1. Design tier & principles

**Tier: a credible institutional instrument, not productized SaaS.** Tonal target:
*a bank compliance memo / a regulator's filing viewer / a stamped audit certificate —
NOT a startup marketing page.* Credibility comes from structure, citation discipline,
and typographic restraint, never from gloss.

- We do **not** match ZeroH's breadth or polish; we are a deliberate **honest subset**
  that makes the narrower thing (decision provenance) more *inspectable*.
- **Effort concentration** (per viewer-first lock): evidence viewer > playground >
  README/verification > demo video > diagrams > landing.
- Subtraction default: if an element doesn't earn its pixels, cut it. No decorative
  cards, shadows, gradients, blobs, or illustration.

## 2. Persona → surface map (surfaces are NOT co-equal)

| Surface | Committee reader (PRIMARY, non-technical) | Dev / bank validator (CO-PRIMARY) |
|---|---|---|
| Landing hero + top third | **leads** | below the fold |
| Playground | **primary interaction** | secondary |
| Evidence viewer | **the climax** | verifies offline instead |
| Demo video (3-min) | yes (decision→committee story) | no |
| README | no | **leads** |
| Diagrams | scholar-attestation flow only | system + data-flow |
| curl / OpenAPI / verifier / REPRODUCIBILITY.md | no | yes |

Rule: **developer content never leads a reader surface.** The reader's first impression
is always decision-first plain language, never an API call or a JSON blob.

## 3. Information architecture (DR1)

**One single-scroll page**, top to bottom:
1. Decision-first plain-language headline + two CTAs (`Try a decision` / `View signed evidence`).
2. Playground scenario picker.
3. **Evidence viewer renders INLINE directly below** (no modal, no route change — the
   decision appears in place; a modal would be dismissible and fight the persistent UNCERTIFIED rule).
4. Developer door (curl, signed-envelope JSON, MIT/GitHub, OpenAPI) **below the fold**.

README + system/data-flow diagrams live in the repo, not on this page.

## 4. Aesthetic system

### Typography
- **IBM Plex Serif** — certificate titles, landing headline, section "names" only.
- **IBM Plex Sans** — all UI/body.
- **IBM Plex Mono** — hashes, signatures, versions, IDs, status strips.
- a11y-max swap: **Atkinson Hyperlegible** may replace Plex Sans for body if field
  testing shows legibility issues with the older-skew audience.
- No system-ui/Inter/Roboto/Arial as a primary display face (AI-slop tell #11).
- Body text ≥ 16px on the landing; ≥ 12.5px in the dense certificate tables.

### Color tokens
```css
/* surfaces */
--paper:#F8F9F5;   --ink:#15201a;   --muted:#5d6b60;   --rule:#cfd8cc;
--mono-bg:#EEF1E9; --ink-block:#161412;   /* inked DENY block + status strips */
/* brand (heritage green — sober, NOT a bright SaaS emerald) */
--green:#14452F;
/* DECISION SEMANTICS — escalating weight, never color alone */
--allow:#1F6B3B;   /* light block + check glyph  (the ONLY semantic use of green) */
--review:#9C5A12;  /* amber block + caution glyph (a discipline, not a failure)   */
--deny:#161412;    /* heavy INKED block, paper text + slash glyph (a valid result) */
/* status / chrome (NOT a decision color) */
--ochre:#9C5A12; --ochre-band:#EFE6CE; --ochre-ink:#6f3d08;  /* UNCERTIFIED */
--error:#B00020;   /* ALARM RED — reserved for SYSTEM ERRORS ONLY, never a DENY */
```
- **Green is brand chrome + the ALLOW semantic only.** Do not flood the UI green
  (that is ZeroH's lane and reads derivative).
- **Decision states carry an icon + word + weight**, so they survive grayscale and
  colorblindness. ALLOW (light/green/✓) < REVIEW (amber/caution) < DENY (inked block/✕).
- **UNCERTIFIED uses a diagonal-hatch ochre band** — a non-color "provisional" signal
  distinct from all three decision colors and from the alarm-red error.
- Verify AA contrast on `--allow` and `--ochre-ink` when used as small text; pair with
  weight/size or darken if a token fails 4.5:1.

### Structure & motion
- Hierarchy from **spacing, alignment, and ruled sections** — hairline rules, ruled
  tables, certificate headers. No drop shadows. No gradients. No bubbly radii.
- Motion is **functional only** (API-state reveals, loading). Honor `prefers-reduced-motion`.

## 5. Evidence-artifact viewer — the "decision certificate" (DX8 styled)

Render as an **audit exhibit**, dense/aligned/printable, never raw JSON or app cards.
**Field rank, top → bottom:**
1. **UNCERTIFIED hatch band** (sticky/persistent) + forward-projection line (§ below).
2. **Decision + named reason** — largest. `DENY` in the inked block, `MAYSIR — gambling`,
   one plain-language explanation line.
3. **Basis for decision** — ruled table: matched rule (mono) · human reason · **AAOIFI
   slot labeled `pending — populated on v1.0 certification`** (a styled placeholder, never
   blank — a blank reads "broken/unserious" to a scholar). Then rule-pack version + sha256
   hash (mono). Then the **illustrative Maqasid line** (DR4): `Maqasid (illustrative):
   protects Ḥifẓ al-Māl — preservation of wealth` + an explicit `illustrative, not
   computed at v0.1` tag (so it never reads as computed analysis).
4. **Madhab position** — formal notice naming Hanafi · Maliki · Shafiʿi · Hanbali, stating
   `v0.1 encodes the Hanafi position; a certified version would state coverage per your
   committee's madhab`. **No four-way comparison UI** (locked).
5. **Verify affordance — at the BOTTOM** (it serves the dev lens; must not outrank the
   reader's decision): copy command (`npm run verify:fixture`), signature/hash/replay
   status, public-key fingerprint, download-envelope.

### The honesty pattern (DX11) — unavoidable, but rigor not toy
Persistent, **non-dismissible** treatment (a modal/footer-badge silently violates the
"unavoidable" lock): full-width hatch-ochre top band `UNCERTIFIED — synthetic demo rule
pack`, secondary `Not a fatwa · not certified · not production advice`, a repeated amber
`Uncertified` chip by the title, and a faint diagonal watermark `COMMITTEE-REVIEWABLE
DEMO EVIDENCE`. Amber/ochre, **never red** (a DENY is a valid result, not a failure;
red is errors-only). Precedent: investigational-use / specimen labeling — deliberate.

### Forward projection (DR3) — completes the reader's arc, stays honest
Beside the honesty signals, add **future-conditional** microcopy: `This demo shows the
exact evidence shape a certified v1.0 pack produces — the AAOIFI citation and scholar
signature populate on certification.` **Copy guard: never let "would produce" drift to
"does produce."** It must never imply a certified version currently exists.

### Error ≠ deny (highest-risk separation)
A decision (allow/deny/review) renders a **signed certificate**. A system/integration
failure renders a **dashed problem panel — never a certificate, never deny-colored,
unsigned 4xx, no envelope exists** (alarm-red, distinct icon). The artifact-type
difference is the primary separation; color is secondary.

## 6. Playground interaction states (DR2)

| State | What the reader sees |
|---|---|
| No decision (initial) | Scenario picker + an **empty certificate shell** (ghosted field outline), not a blank panel. "Pick a scenario to see a signed decision." |
| Loading | "Authorizing intent…" with the intent summary kept visible + a step indicator. |
| Slow (>~2s) | "Still waiting for the API…", request stays visible, reassure. |
| Success | Certificate renders inline. Include a pre-canned **REVIEW** scenario (UC2 mixed-revenue ETF) so REVIEW is reachable and gets its amber first-class treatment, not a grey "couldn't decide". |
| API error | **Dashed problem panel**, structurally distinct from a DENY certificate; problem+json detail. |
| Invalid input (raw hatch) | Schema error beside the edited JSON (offending field + allowed values), not a toast. Hatch stays labeled "advanced / unsupported". |

## 7. Landing spec (B direction)

Decision-first scholar-framed headline (NOT dev-framed). The **decision certificate is
the hero visual anchor** (right), not abstract Islamic geometry. Two CTAs only. A ruled
horizontal `intent → rule pack → signed decision` flow (NOT a 3-column icon-card grid).
Forward-projection strip. Developer door below the fold (curl + offline-verify + MIT/
OpenAPI links). Monospace status strips top + bottom carry `ENGINE · VERSION · RULESET ·
JURISDICTION · LICENSE` and keep UNCERTIFIED visible. See `landing-mockup.html`.

**HTTP-contract call-out (DT1 + DX9 — state BOTH halves, never just one):** the curl block
must show that a *decision* is **always 200** (a DENY is 200 — read the body, not the
status; this is the DT1 anti-footgun that stops an agent reading 200-DENY as "approved")
**AND** that *malformed input* is **4xx problem+json, never a signed decision** (DX9). Showing
only "always 200" reads as a naive no-error-handling API; showing only 4xx loses the DT1
call-out. This is **error≠deny at the HTTP layer** — the same split as the viewer's
certificate-vs-dashed-panel.

## 8. Demo video (3-min storyboard, DR3) — reader-targeted

Beats: (1) the problem in one line → (2) pick "agent books a casino-hotel" → (3) DENY +
cited reason in the viewer → (4) the evidence envelope → (5) verify it offline (PASS, then
tamper → FAIL) → (6) what certification adds (the forward projection + uncertified limits).
NOT a curl/verify screencast for developers.

## 9. Architecture diagrams (DR7) — split by persona

- **Reader-facing scholar-attestation flow**: ONE hand-built **SVG in this design system**
  (heritage-green, IBM Plex, ruled), on the page near the viewer — draws how certification
  slots into the evidence chain (carries the forward projection).
- **Developer-facing system + data-flow**: **Mermaid** in the README (GitHub-native,
  zero-dependency). One consistent notation; do not let three diagrams arrive in three styles.

## 10. README visual style

Document-grade markdown matching this system: a one-line value prop, a copy-paste
quickstart (`npm i` → `npm run verify:fixture`), the always-200 machine-contract call-out,
the honesty disclaimer, the Mermaid system/data-flow diagrams, links to REPRODUCIBILITY.md
+ OpenAPI. Sober, no badge soup.

## 11. Responsive & accessibility baseline (DR6)

- **WCAG 2.2 AA** contrast (verify `--allow`/`--ochre-ink` as small text).
- Full keyboard nav + visible focus rings; 44px min touch targets.
- `prefers-reduced-motion` honored (near-zero motion anyway).
- Responsive single-scroll: the playground/viewer workspace stacks on mobile; the basis
  table reflows; the certificate stays legible.
- **Print stylesheet**: the certificate prints as a clean committee paper-trail page
  (delivers the "PDF audit export" value now, for free).
- RTL / full-Arabic deferred to post-certification (transliterated terms only at v0.1) — see TODO T-24.

## 12. AI-slop blacklist (guard every surface against these)

No purple/violet/indigo gradients; no 3-column icon-in-colored-circle feature grid; no
centered-everything; no uniform bubbly radii; no decorative blobs/wavy dividers; no emoji
as design elements; no colored-left-border cards; no generic hero copy ("Unlock the power
of…"); no system-ui as the primary display face; no cookie-cutter hero→3-features→CTA rhythm.

## 13. Honesty wording (DX11) — binding design constraints

Use verbatim: "synthetic demo rule pack" · "not a fatwa / not certified / not production
advice" · "committee-reviewable demo evidence" (**never** "board-readable"). UNCERTIFIED
must be unavoidable on the viewer. Decision provenance, **not** redaction proof (stay clear
of the ZeroH GB2604344.8 masking/selective-disclosure patent).

**Public-content discipline (IT-05 / F-3.A) — binding on every public surface.** NO named
bank or scholar appears in the landing, playground scenarios, demo video, screenshots, or
README. The source use cases UC1-3 carry specific prospect-bank names as INTERNAL spec
only — public scenario labels and the demo-video script MUST use generic descriptors
("agent books a casino-hotel", "agent rebalances a mixed-revenue ETF", "agent sets up a
subscription"). This is an explicit T-D8 copy-guard check (a name leak from UC1-3 is the
easy slip).

## 14. References

GOV.UK Design System (sober task-first public-service UI) · SEC/XBRL filing viewers
(machine-readable data → reviewable documents) · IBM Plex (open, distinctive, document-grade)
· Atkinson Hyperlegible (a11y). Decision-certificate / audit-exhibit, not SaaS dashboard.

## 15. NOT in scope (design deferrals)

- Four-madhahib comparison UI (locked out — implies certification breadth not held).
- ZeroH-style on-device masking / redaction-proof widget (their patent; we are provenance).
- Maqasid as *computed* analysis (v0.1 shows ONE illustrative line only).
- Full Arabic RTL localization (post-cert).
- PDF export beyond the print stylesheet (v1.0).
- Bespoke design tooling / image pipeline (agentic-coded HTML/CSS only, minimal deps).
