# Demo video storyboard — 3 minutes, six beats (DESIGN.md §8)

**Audience: the committee reader.** This is the decision→committee story for a
non-technical reviewer — *not* a curl/verify screencast for developers. The
camera follows a decision from intent to committee-reviewable evidence; every
technical surface that appears is narrated in plain language. Total runtime
**3:00**, six beats, locked order per `DESIGN.md` §8.

> **UNCERTIFIED — synthetic demo rule pack.** Everything filmed is a
> **synthetic demo rule pack** — **not a fatwa / not certified / not production
> advice**. What the video shows is **committee-reviewable demo evidence**.
> Scenario labels are generic ("casino-hotel", "mixed-revenue ETF",
> "subscription"); **no real institution, scholar, merchant, customer, or PII
> appears in any frame** (this is the T-D8 copy-guard line; check it against
> every frame before recording). All forward-looking lines stay
> future-conditional: a certified version *would* — never *does*.

## Beat map

| # | Beat (locked, §8) | Time | Duration |
|---|---|---|---|
| 1 | The problem in one line | 0:00–0:20 | 20s |
| 2 | Pick "agent books a casino-hotel" | 0:20–0:45 | 25s |
| 3 | DENY + cited reason in the viewer | 0:45–1:20 | 35s |
| 4 | The evidence envelope | 1:20–1:50 | 30s |
| 5 | Verify it offline — PASS, then tamper → FAIL | 1:50–2:30 | 40s |
| 6 | What certification adds — forward projection + uncertified limits | 2:30–3:00 | 30s |

---

### Beat 1 — the problem in one line (0:00–0:20)

- **On-screen visual:** the landing page hero (build target:
  `design/landing-mockup.html`), static, paper background, serif headline. The
  monospace status strip (`ENGINE · VERSION · RULESET · JURISDICTION ·
  LICENSE`) is visible at the top of frame. No motion except a slow scroll
  settle; no logos of any institution.
- **Voiceover:** *"AI agents are starting to spend money on people's behalf.
  When an agent pays, who checked that the payment was compliant, and can
  anyone prove what was checked? Today that proof usually does not exist."*
- **Honesty marker in frame:** the landing's UNCERTIFIED hatch-ochre band:
  `UNCERTIFIED — synthetic demo rule pack`, persistent at the top of the page.
- **Notes:** hold the headline at least 3 seconds before any movement; the
  reader must be able to finish it.

### Beat 2 — pick "agent books a casino-hotel" (0:20–0:45)

- **On-screen visual:** cursor moves to the playground scenario picker and
  selects the generic scenario card **"agent books a casino-hotel"**. The
  intent summary renders as a short plain-language list (merchant category:
  hotel; attributes: casino, gambling; amount: EUR 420 — all synthetic). The
  empty certificate shell (ghosted field outline, DR2 initial state) is visible
  below, then the loading state: *"Authorizing intent…"* with the intent
  summary kept visible.
- **Voiceover:** *"Here, a synthetic test case. An agent tries to book a stay
  at a casino-hotel. We ask the engine for a decision before any money
  moves."*
- **Honesty marker in frame:** the persistent UNCERTIFIED band stays pinned
  while scrolling; the scenario card carries its `synthetic` tag.
- **Notes:** scenario labels on camera are exactly the generic set
  ("casino-hotel", "mixed-revenue ETF", "subscription"). Never type a real
  merchant or bank name into the hatch, even briefly — edits are filmed, and
  frames get screenshotted.

### Beat 3 — DENY + cited reason in the viewer (0:45–1:20)

- **On-screen visual:** the decision certificate renders **inline** (DR1, no
  modal): the climax surface (build target:
  `design/evidence-viewer-chosen.html`). The inked DENY block (paper text,
  slash glyph — **never red**; red is reserved for system errors) with the
  named reason `MAYSIR — gambling` and one plain-language explanation line.
  Camera then pans down the **Basis for decision** ruled table: matched rule
  `MAYSIR-ATTR` (mono), the human reason, the AAOIFI slot reading `pending —
  populated on v1.0 certification`, the rule-pack version + sha256 hash, and
  the illustrative Maqasid line with its `illustrative, not computed at v0.1`
  tag.
- **Voiceover:** *"The decision is deny, and it is not a black box. The
  certificate names the rule that matched, the reason in plain language, and
  the exact version of the rule pack that decided it. The slot for the formal
  standard citation is reserved, and labeled as pending, because this demo
  pack is uncertified."*
- **Honesty marker in frame:** the full DX11 stack on the certificate: the
  hatch-ochre band `UNCERTIFIED — synthetic demo rule pack`, the secondary
  line `Not a fatwa · not certified · not production advice`, the amber
  `Uncertified` chip by the title, and the faint diagonal watermark
  `COMMITTEE-REVIEWABLE DEMO EVIDENCE`.
- **Notes:** this is the longest-held surface in the video — it is the product.
  A DENY is presented as a *valid result*, calm and final, not an alarm.

### Beat 4 — the evidence envelope (1:20–1:50)

- **On-screen visual:** scroll to the bottom of the certificate to the verify
  affordance: signature status, public-key fingerprint (`did:key:…`,
  truncated mono), the rule-pack hash, and the download-envelope control. A
  brief, dimmed glimpse of the signed envelope JSON (decision, reason codes,
  hashes highlighted; the long signature string mostly out of frame) — shown
  as "what the certificate is made of", not as code to read.
- **Voiceover:** *"Behind the certificate is a sealed evidence envelope. It
  records the intent, the decision, the reasons, and a fingerprint of the
  exact rule pack, and the whole record is cryptographically signed. Change
  one character anywhere and the seal breaks."*
- **Honesty marker in frame:** inside the envelope JSON, the
  `scholar_signature_ref` block is visibly `"status": "uncertified"` with its
  statement line `synthetic demo rule pack — not a fatwa / not certified / not
  production advice`.
- **Notes:** keep the JSON dimmed and brief (~5s); the committee reader needs
  the *idea* of the sealed record, not the syntax.

### Beat 5 — verify it offline: PASS, then tamper → FAIL (1:50–2:30)

- **On-screen visual:** a clean, large-type terminal (IBM Plex Mono, paper
  palette — a styled prop, not a developer's cluttered screen). One command
  runs; the verifier's check list appears line by line, ending **`RESULT:
  PASS — decision "deny"`**. Then, on screen, one character of the saved
  evidence file is visibly changed (a single highlighted byte flip); the same
  command runs again and ends **`RESULT: FAIL`**. The FAIL treatment is the
  inked/neutral verdict style with a slash glyph — **not alarm-red**: a broken
  seal is a *finding* the system is designed to produce, not a system error.
- **Voiceover:** *"Anyone can check this evidence on their own computer,
  without trusting our server, using a small open verifier. It passes. Now we
  change a single character of the record and check again. It fails. That is
  the point: this evidence cannot be quietly edited."*
- **Honesty marker in frame:** the verifier's final output line is kept in
  frame: `NOTE: UNCERTIFIED — synthetic demo rule pack; not a fatwa / not
  certified / not production advice.`
- **Notes:** show exactly one command and its result, twice. No scrolling
  through flags or source; this beat proves independence to a reader, it does
  not teach tooling. (Developers get `REPRODUCIBILITY.md` instead.)

### Beat 6 — what certification adds (2:30–3:00)

- **On-screen visual:** return to the certificate, slow push-in on two slots
  side by side: the `standards_ref` line (`pending — populated on v1.0
  certification`) and the scholar-signature slot (`status: uncertified`,
  scholar `did:key` empty). Beside them, the forward-projection strip renders
  the locked DR3 microcopy: *"This demo shows the exact evidence shape a
  certified v1.0 pack produces — the AAOIFI citation and scholar signature
  populate on certification."* End card: paper background, the UNCERTIFIED
  band, repository URL, MIT license line, monospace status strip.
- **Voiceover:** *"What you saw is a demonstration, built on a synthetic demo
  rule pack. It is not a fatwa, not certified, and not production advice. A
  certified version would carry the formal standard citation in that reserved
  slot, and a scholar's own signature over the rule pack itself, so the
  evidence your committee reviews would arrive already sealed, already
  citable, and independently checkable. That is what certification would
  add."*
- **Honesty marker in frame:** all of them at once: the hatch band, the
  `Uncertified` chip, the watermark, and the future-conditional projection
  strip — the video **ends on the limits**, not on a claim.
- **Notes:** the copy guard is hardest here: every sentence about v1.0 stays
  conditional (*would carry*, *would arrive*). If a recorded take says "does"
  or "will", re-record the take.

---

## Production notes (binding)

- **Surfaces:** film the real W3-4 pages built to `DESIGN.md` and the
  `design/*.html` targets; the terminal in beat 5 is the only non-browser
  surface.
- **Type & color:** IBM Plex Serif/Sans/Mono on the paper palette. Decision
  semantics carry icon + word + weight: ALLOW light/green/check, REVIEW
  amber/caution, DENY inked block/slash. **UNCERTIFIED is always the
  hatch-ochre band, never red.** Alarm red (`#B00020`) may appear in this
  video **nowhere** — no system error is ever on camera.
- **Motion:** functional only — state reveals and the beat-5 byte flip. No
  zoom-bounce, no decorative transitions.
- **Sound:** voiceover only; no music bed required (if one is added, keep it
  under the institutional register — no startup synth).
- **Error ≠ deny discipline:** the video shows decisions and verification
  verdicts only. If an API failure happens during filming, cut it or reshoot —
  a dashed problem panel appearing mid-demo would need its own explanation and
  this story has no room for it.
- **Copy-guard checklist before publishing (T-D8):**
  1. No real institution, bank, scholar, merchant, or person named or shown in
     any frame, caption, or file path.
  2. Scenario labels exactly: "casino-hotel", "mixed-revenue ETF",
     "subscription".
  3. Honesty wording verbatim where decisions are shown: "synthetic demo rule
     pack" · "not a fatwa / not certified / not production advice" ·
     "committee-reviewable demo evidence" (never "board-readable").
  4. Every forward-looking sentence is future-conditional ("would"), including
     ad-libbed voiceover.
  5. UNCERTIFIED visible in **every** frame that shows a decision.
