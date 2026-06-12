/**
 * Pure DOM builders for the playground's interaction states (DESIGN.md §6) and
 * the decision certificate (DESIGN.md §5). No fetch, no timers — the controller
 * (app.js) owns side effects; everything here is unit-testable in a DOM.
 *
 * The error ≠ deny guard, structurally:
 *   - renderCertificate() is the ONLY function that produces <article class="sheet">
 *     with the UNCERTIFIED certificate band — and it requires a decision body
 *     that carries a signed evidence_artifact;
 *   - renderProblemPanel() produces <aside class="problem-panel"> — dashed,
 *     alarm-red, NEVER a certificate node, NEVER the certificate band.
 *
 * All response/problem data is inserted via textContent (never markup).
 */
import { intentSummary } from "./scenarios.js";

/** Static, trusted SVG glyphs (decision states + system error). */
const GLYPHS = {
  allow:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" aria-hidden="true"><path d="M5 12.5l4.2 4.2L19 7"/></svg>',
  review:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><circle cx="12" cy="12" r="9"/><line x1="12" y1="7.5" x2="12" y2="13"/><circle cx="12" cy="16.6" r="1.1" fill="currentColor" stroke="none"/></svg>',
  deny:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><circle cx="12" cy="12" r="9"/><line x1="6.4" y1="6.4" x2="17.6" y2="17.6"/></svg>',
  error:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><path d="M12 4 L21 19 H3 Z"/><line x1="12" y1="10" x2="12" y2="14"/><circle cx="12" cy="16.6" r="1.1" fill="currentColor" stroke="none"/></svg>',
};

/**
 * Closed reason-code → short human label map: the shipped pack's codes plus the
 * engine-level credential-scope code (AGENT_SCOPE_EXCEEDED). Any unmapped code
 * still renders as its raw string (graceful), but every code the engine can emit
 * has a label here.
 */
export const REASON_LABELS = {
  MAYSIR: "gambling",
  INTOXICANTS: "intoxicants",
  RIBA: "interest",
  GHARAR: "excessive uncertainty",
  MIXED_REVENUE: "mixed impermissible revenue",
  AGENT_SCOPE_EXCEEDED: "agent credential scope exceeded",
};

const AAOIFI_PENDING = "pending — populated on v1.0 certification";

/** Engine-level reason code for a credential-scope deny (src/vc/enforce.ts). */
const AGENT_SCOPE_EXCEEDED = "AGENT_SCOPE_EXCEEDED";

/**
 * A credential-scope deny: the rule pack matched nothing, but the presented
 * agent credential's allowed-MCC scope excluded the merchant, so the engine
 * denied. Distinguished from a pack-default ALLOW (which also has no matched
 * rules) so the certificate never labels a deny as a default allow.
 */
function isScopeDeny(body) {
  return (
    String(body.decision) === "deny" &&
    Array.isArray(body.reason_codes) &&
    body.reason_codes.includes(AGENT_SCOPE_EXCEEDED)
  );
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function glyph(kind, className) {
  const node = el("div", className);
  node.innerHTML = GLYPHS[kind] ?? GLYPHS.error; // trusted constants only
  return node;
}

/** The persistent UNCERTIFIED hatch band (DX11 — unavoidable, amber, never red). */
function uncertBand() {
  const band = el("div", "uncert");
  const inner = el("div", "uncert-inner");
  inner.append(
    el("b", "", "Uncertified — synthetic demo rule pack"),
    el("span", "", "Not a fatwa · not certified · not production advice"),
  );
  band.append(inner);
  return band;
}

function watermark() {
  const mark = el("div", "watermark");
  mark.setAttribute("aria-hidden", "true");
  return mark;
}

/* ------------------------------------------------------------------ */
/* state 1 — initial: the empty certificate shell (never a blank panel) */
/* ------------------------------------------------------------------ */

export function renderEmptyShell() {
  const sheet = el("article", "sheet sheet--empty");
  sheet.setAttribute("aria-label", "No decision yet");
  sheet.append(uncertBand());

  const body = el("div", "ghost-body");
  const decision = el("div", "ghost-decision");
  const ghostGlyph = el("div", "ghost-glyph");
  ghostGlyph.setAttribute("aria-hidden", "true");
  const lines = el("div", "ghost-lines");
  lines.setAttribute("aria-hidden", "true");
  lines.append(el("div", "ghost-line w60"), el("div", "ghost-line w40"));
  decision.append(ghostGlyph, lines);

  const table = el("div", "ghost-table");
  table.setAttribute("aria-hidden", "true");
  table.append(el("div", "ghost-line"), el("div", "ghost-line w80"), el("div", "ghost-line w70"));

  body.append(decision, el("p", "empty-msg", "Pick a scenario to see a signed decision."), table);
  sheet.append(body);
  return sheet;
}

/* ------------------------------------------------------------- */
/* states 2 + 3 — loading, and the >2s slow copy swap (no fakery) */
/* ------------------------------------------------------------- */

/**
 * @param {Record<string, any>} intent the intent in flight (summary stays visible)
 * @param {"loading"|"slow"} [phase]
 */
export function renderLoading(intent, phase = "loading") {
  const box = el("div", "viewer-state loading-state");
  box.dataset.phase = phase;
  box.append(
    el(
      "p",
      "loading-copy",
      phase === "slow" ? "Still waiting for the API…" : "Authorizing intent…",
    ),
    el("p", "intent-summary", `Intent: ${intentSummary(intent)}`),
  );

  const steps = el("ol", "steps-mini");
  for (const [index, label] of [
    "payment intent",
    "rule pack evaluates",
    "signed decision + evidence",
  ].entries()) {
    const step = el("li", "", `${String(index + 1).padStart(2, "0")} ${label}`);
    if (index === 1) step.dataset.active = "true"; // the evaluation is what we wait on
    steps.append(step);
  }
  box.append(steps);

  if (phase === "slow") {
    box.append(
      el(
        "p",
        "slow-note",
        "The request is still in flight — nothing was lost. The decision renders here the moment the API answers.",
      ),
    );
  }
  return box;
}

/* ----------------------------------------------------- */
/* state 4 — success: the decision certificate (T-D1, §5) */
/* ----------------------------------------------------- */

function reasonHeadline(body) {
  const codes = Array.isArray(body.reason_codes) ? body.reason_codes : [];
  if (codes.length === 0) return "no prohibition matched — pack default applies";
  return codes
    .map((code) => (REASON_LABELS[code] ? `${code} — ${REASON_LABELS[code]}` : String(code)))
    .join(" · ");
}

function explanationLine(body) {
  const rules = Array.isArray(body.matched_rules) ? body.matched_rules : [];
  const first = rules[0];
  if (first && typeof first.description === "string") return first.description;
  if (isScopeDeny(body)) {
    return "No rule pack rule matched, but the presented agent credential's allowed-MCC scope excludes this merchant's MCC — the engine denied (AGENT_SCOPE_EXCEEDED).";
  }
  return "No rule in the synthetic demo pack matched this intent; the pack's default decision applies (category-level screening only).";
}

function decisionBlock(body) {
  const decision = String(body.decision);
  const block = el("div", "decision");
  block.append(glyph(decision, "glyph"));
  const text = el("div");
  text.append(
    el("div", "dlabel", decision.toUpperCase()),
    el("div", "dreason", reasonHeadline(body)),
    el("div", "dexpl", explanationLine(body)),
  );
  block.append(text);
  return block;
}

function basisSection(body) {
  const sec = el("section", "sec basis");
  sec.append(el("h3", "", "Basis for decision"));

  const wrap = el("div", "table-wrap");
  const table = el("table");
  const head = el("tr");
  head.append(el("th", "", "Matched rule"), el("th", "", "Reason"), el("th", "", "AAOIFI standard"));
  table.append(head);

  const rules = Array.isArray(body.matched_rules) ? body.matched_rules : [];
  if (rules.length === 0) {
    // No pack rule matched. Two distinct outcomes share this shape: a pack-default
    // ALLOW, and a credential-scope DENY (the basis is the credential, not a pack
    // rule). Label each honestly so a deny is never shown as a default allow.
    const scopeDenied = isScopeDeny(body);
    const row = el("tr");
    row.append(
      el("td", "k mono", scopeDenied ? "(agent credential)" : "(no rule matched)"),
      el(
        "td",
        "",
        scopeDenied
          ? "Scope exceeded — merchant MCC not in the credential's allowed_mcc"
          : "Pack default decision — allow",
      ),
      el("td", "pending", AAOIFI_PENDING), // the placeholder is styled, never blank
    );
    table.append(row);
  } else {
    for (const rule of rules) {
      const row = el("tr");
      row.append(
        el("td", "k mono", String(rule.rule_id ?? "")),
        el("td", "", String(rule.title ?? "")),
        // ALWAYS the styled pending placeholder at v0.1 — a blank reads broken.
        el("td", "pending", typeof rule.standards_ref?.note === "string" ? rule.standards_ref.note : AAOIFI_PENDING),
      );
      table.append(row);
    }
  }
  wrap.append(table);
  sec.append(wrap);

  // provenance rows: the complete replay key (rule_pack_hash + evaluator_version + intent_hash)
  const metaWrap = el("div", "table-wrap");
  const meta = el("table");
  meta.style.marginTop = "9px";
  for (const [key, value] of [
    ["Rule pack", `${String(body.rule_pack_id)} · version ${String(body.rule_pack_version)}`],
    ["Pack hash", `sha256:${String(body.rule_pack_hash)}`],
    ["Evaluator", `${String(body.evaluator_version)} · deterministic — no LLM in the decision path`],
    ["Intent hash", `sha256:${String(body.intent_hash)}`],
  ]) {
    const row = el("tr");
    const k = el("td", "k", key);
    k.style.width = "34%";
    row.append(k, el("td", "mono", value));
    meta.append(row);
  }
  metaWrap.append(meta);
  sec.append(metaWrap);

  // illustrative Maqasid line (DR4) — explicitly tagged, never reads as computed
  const maqasid = el("div", "maqasid");
  maqasid.append(
    el("b", "", "Maqasid (illustrative):"),
    document.createTextNode(" protects Ḥifẓ al-Māl — preservation of wealth. "),
    el("i", "", "illustrative mapping, not computed at v0.1"),
  );
  sec.append(maqasid);
  return sec;
}

function madhabNotice() {
  const notice = el("div", "madhab");
  notice.append(
    el("b", "", "Madhab position"),
    el("span", "schools", "Hanafi · Maliki · Shafiʿi · Hanbali."),
    document.createTextNode(
      " v0.1 encodes the Hanafi position; the other three schools are not represented. A certified version would state coverage per your committee's madhab.",
    ),
  );
  return notice;
}

/** Best-effort kid extraction from the JWS protected header (display only). */
function kidFromJws(jws) {
  try {
    const headerB64 = String(jws).split(".")[0];
    const json = atob(headerB64.replace(/-/g, "+").replace(/_/g, "/"));
    const header = JSON.parse(json);
    return typeof header.kid === "string" && header.kid !== "" ? header.kid : "(unknown)";
  } catch {
    return "(unknown)";
  }
}

function verifyStat(check, state, markerText, text) {
  const stat = el("div", "vstat");
  stat.dataset.check = check;
  stat.dataset.state = state;
  stat.append(el("span", "marker", markerText), el("span", "vtext", text));
  return stat;
}

function verifySection(body) {
  const verify = el("section", "verify");
  verify.append(el("h3", "", "Verify this yourself — trust nothing on our server"));

  const cmd = el("div", "cmd");
  const cmdText = `node verifier/verify.mjs --evidence ${String(body.decision_id)}.jws --jwks jwks.json --pack pack.json`;
  cmd.append(el("span", "cmd-text", cmdText));
  const copy = el("button", "copy", "copy");
  copy.type = "button";
  copy.dataset.action = "copy-command";
  copy.dataset.command = cmdText;
  copy.setAttribute("aria-label", "Copy the offline verify command");
  cmd.append(copy);
  verify.append(cmd);

  const row = el("div", "vrow");
  row.append(
    verifyStat("signature", "pending", "…", "Checking the Ed25519 signature in this browser…"),
    verifyStat("pack-hash", "pending", "…", "Checking the rule-pack hash against the served pack…"),
    verifyStat(
      "replay",
      "na",
      "○",
      `Replay — re-derive ${String(body.decision).toUpperCase()} offline: npm run replay`,
    ),
  );
  verify.append(row);

  verify.append(
    el(
      "p",
      "vnote",
      "In-browser checks consult this same server. For independent proof, run the offline verifier — node built-ins only, zero server trust.",
    ),
  );

  verify.append(el("div", "fp", `issuer key kid ${kidFromJws(body.evidence_artifact)} · compare against the issuer's published key obtained out-of-band`));

  const artifacts = el("div", "artifact-row");
  const download = el("button", "download", "Download envelope (.jws)");
  download.type = "button";
  download.dataset.action = "download-envelope";
  const jwksLink = el("a", "", "jwks.json");
  jwksLink.setAttribute("href", "/.well-known/jwks.json");
  jwksLink.setAttribute("download", "jwks.json");
  const packLink = el("a", "", "pack.json");
  packLink.setAttribute(
    "href",
    `/rule-packs/${encodeURIComponent(String(body.rule_pack_id))}/${encodeURIComponent(String(body.rule_pack_version))}`,
  );
  packLink.setAttribute("download", "pack.json");
  artifacts.append(download, jwksLink, packLink);
  verify.append(artifacts);

  return verify;
}

/**
 * The decision certificate — an audit exhibit, field rank per DESIGN.md §5.
 * Requires a decision body WITH a signed evidence_artifact (error ≠ deny:
 * nothing unsigned may ever look like a certificate).
 * @param {Record<string, any>} body the /authorize 200 response body
 */
export function renderCertificate(body) {
  if (typeof body.evidence_artifact !== "string" || body.evidence_artifact === "") {
    throw new Error("refusing to render a certificate without a signed evidence artifact");
  }
  const sheet = el("article", "sheet certificate");
  sheet.dataset.decision = String(body.decision);
  sheet.setAttribute("aria-label", `Authorization decision: ${String(body.decision)}`);

  // head block
  const chead = el("div", "chead");
  const headText = el("div");
  headText.append(
    el("div", "t", "Authorization Decision — Evidence Record"),
    el("div", "sub", `${String(body.decision_id)} · ${String(body.decision_timestamp)}`),
  );
  chead.append(headText, el("span", "chip", "Uncertified"));

  sheet.append(
    watermark(),
    uncertBand(), // rank 1 — sticky, non-dismissible
    el(
      "p",
      "project-line",
      "This demo shows the exact evidence shape a certified v1.0 pack produces — the AAOIFI citation and scholar signature populate on certification.",
    ),
    chead,
    decisionBlock(body), // rank 2 — decision + named reason, largest
    basisSection(body), // rank 3 — basis table + provenance + Maqasid
    madhabNotice(), // rank 4 — formal notice, no four-way comparison UI
    verifySection(body), // rank 5 — verify affordance at the BOTTOM
    el("div", "foot", "Decision provenance · not redaction proof · synthetic intent · no PII · MIT"),
  );
  return sheet;
}

/* ------------------------------------------------------------------- */
/* state 5 — API error: the DASHED problem panel (NEVER a certificate)  */
/* ------------------------------------------------------------------- */

/**
 * @param {{title?:string,detail?:string,status?:number|null,type?:string,instance?:string}} view
 */
export function renderProblemPanel(view) {
  const panel = el("aside", "problem-panel");
  panel.dataset.kind = "problem";
  panel.setAttribute("aria-label", "System error — not a decision");
  // role=alert announces an integration failure assertively (it interrupts),
  // rather than queuing behind the polite evidence-region updates a decision uses.
  panel.setAttribute("role", "alert");

  const head = el("div", "pp-head");
  head.append(glyph("error", "pp-glyph"), el("p", "pp-name", "SYSTEM ERROR — NOT A DECISION"));
  panel.append(head);

  panel.append(el("p", "pp-title", typeof view.title === "string" ? view.title : "Request failed"));
  panel.append(
    el(
      "p",
      "pp-detail",
      typeof view.detail === "string"
        ? view.detail
        : "The request failed before a decision could be made.",
    ),
  );

  const metaParts = [];
  if (typeof view.status === "number") metaParts.push(`HTTP ${String(view.status)} · application/problem+json`);
  else metaParts.push("no HTTP response");
  if (typeof view.type === "string" && view.type !== "about:blank") metaParts.push(view.type);
  panel.append(el("p", "pp-meta", metaParts.join(" · ")));

  panel.append(
    el(
      "p",
      "pp-note",
      "An integration failure renders this dashed panel — never a decision certificate. Nothing was signed and no evidence envelope exists (error ≠ deny).",
    ),
  );
  return panel;
}

/* --------------------------------------------------------------------- */
/* state 6 — invalid input: schema errors BESIDE the raw-JSON hatch editor */
/* --------------------------------------------------------------------- */

/**
 * @param {{kind?:string,message?:string,detail?:string,issues?:Array<{field?:string,message?:string,allowed_values?:unknown[]}>}} problem
 *   either a local parse failure ({kind:"parse", message}) or a 4xx problem+json document
 */
export function renderInputIssues(problem) {
  const box = el("div", "hatch-problem");
  box.dataset.kind = "input-problem";
  box.append(el("h3", "", "Invalid intent — rejected before evaluation"));

  if (problem.kind === "parse") {
    box.append(el("p", "", `Not valid JSON: ${String(problem.message ?? "unparseable input")}`));
  } else if (Array.isArray(problem.issues) && problem.issues.length > 0) {
    const list = el("ul");
    for (const issue of problem.issues) {
      const item = el("li");
      item.append(el("code", "", String(issue.field ?? "(body root)")));
      let text = ` — ${String(issue.message ?? "invalid value")}`;
      if (Array.isArray(issue.allowed_values)) {
        text += `; allowed values: ${issue.allowed_values.map(String).join(", ")}`;
      }
      item.append(document.createTextNode(text));
      list.append(item);
    }
    box.append(list);
  } else {
    box.append(el("p", "", String(problem.detail ?? "The intent was rejected.")));
  }

  box.append(
    el(
      "p",
      "hatch-problem-foot",
      "Schema errors are 400 problem+json — an integration failure, never a signed decision. This hatch stays advanced / unsupported.",
    ),
  );
  return box;
}
