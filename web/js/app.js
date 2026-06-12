/**
 * Playground controller — wires the scenario picker, the advanced raw-JSON
 * hatch, and the inline evidence viewer (DESIGN.md §3: one single-scroll page,
 * the certificate renders in place — no modal, no route change).
 *
 * State machine per request (DESIGN.md §6):
 *   idle (empty shell) → loading → [>2s: slow copy swap, no artificial delay]
 *     → success (certificate)  | API error (dashed problem panel)
 *   hatch-only: invalid input → schema issues render BESIDE the editor.
 */
import { SCENARIOS } from "./scenarios.js";
import { authorizeIntent, SLOW_THRESHOLD_MS } from "./api.js";
import {
  renderCertificate,
  renderEmptyShell,
  renderInputIssues,
  renderLoading,
  renderProblemPanel,
} from "./render.js";
import { sha256HexOfText, verifyEnvelopeSignature } from "./inpage-verify.js";

const region = document.getElementById("evidence-region");
const picker = document.getElementById("scenario-picker");
const hatchInput = document.getElementById("hatch-input");
const hatchSend = document.getElementById("hatch-send");
const hatchIssues = document.getElementById("hatch-issues");

let requestSeq = 0;
let slowTimer = 0;

function setRegion(node) {
  if (region) region.replaceChildren(node);
}

function clearHatchIssues() {
  if (hatchIssues) hatchIssues.replaceChildren();
}

function setCheck(sheet, check, state, marker, text) {
  if (!sheet.isConnected) return; // a newer render replaced this certificate
  const stat = sheet.querySelector(`[data-check="${check}"]`);
  if (!stat) return;
  stat.dataset.state = state;
  const markerNode = stat.querySelector(".marker");
  const textNode = stat.querySelector(".vtext");
  if (markerNode) markerNode.textContent = marker;
  if (textNode) textNode.textContent = text;
}

/**
 * Courtesy in-page checks (clearly labeled as consulting this same server —
 * the offline verifier stays the independent path).
 * @param {HTMLElement} sheet
 * @param {Record<string, any>} body
 */
async function runInPageChecks(sheet, body) {
  try {
    const response = await fetch("/.well-known/jwks.json");
    const jwks = await response.json();
    const verdict = await verifyEnvelopeSignature(String(body.evidence_artifact), jwks);
    if (verdict.ok) {
      setCheck(sheet, "signature", "ok", "✓", "Ed25519 signature valid — checked in this browser against this server's JWKS");
    } else if (verdict.unsupported) {
      setCheck(sheet, "signature", "na", "○", `Signature not checked here (${verdict.reason ?? "unsupported"}) — run the offline verifier`);
    } else {
      setCheck(sheet, "signature", "fail", "✗", `Signature check FAILED — ${verdict.reason ?? "unknown"}`);
    }
  } catch {
    setCheck(sheet, "signature", "na", "○", "Signature not checked here (JWKS unreachable) — run the offline verifier");
  }

  try {
    const packUrl = `/rule-packs/${encodeURIComponent(String(body.rule_pack_id))}/${encodeURIComponent(String(body.rule_pack_version))}`;
    const response = await fetch(packUrl);
    if (!response.ok) throw new Error(`HTTP ${String(response.status)}`);
    const canonicalBytes = await response.text(); // the route serves exact RFC 8785 canonical bytes
    const digest = await sha256HexOfText(canonicalBytes);
    if (digest === body.rule_pack_hash) {
      setCheck(sheet, "pack-hash", "ok", "✓", "Rule-pack hash matches the served canonical pack (recomputed in this browser)");
    } else {
      setCheck(sheet, "pack-hash", "fail", "✗", "Rule-pack hash does NOT match the served pack");
    }
  } catch {
    setCheck(sheet, "pack-hash", "na", "○", "Pack hash not checked here (rule-pack route unreachable) — run the offline verifier");
  }
}

/** @param {HTMLElement} sheet @param {Record<string, any>} body */
function wireCertificate(sheet, body) {
  const copy = sheet.querySelector('[data-action="copy-command"]');
  if (copy) {
    copy.addEventListener("click", () => {
      const command = copy.getAttribute("data-command") ?? "";
      navigator.clipboard
        .writeText(command)
        .then(() => {
          copy.textContent = "copied";
          setTimeout(() => {
            copy.textContent = "copy";
          }, 1600);
        })
        .catch(() => {
          copy.textContent = "copy failed";
        });
    });
  }

  const download = sheet.querySelector('[data-action="download-envelope"]');
  if (download) {
    download.addEventListener("click", () => {
      // Saves the JWS from the in-page response — the same bytes the offline
      // verifier consumes.
      const blob = new Blob([String(body.evidence_artifact)], { type: "application/jose" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${String(body.decision_id)}.jws`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    });
  }
}

/**
 * Run one authorization round-trip against the real POST /authorize.
 * @param {Record<string, any>} intent
 * @param {boolean} fromHatch schema problems render beside the editor instead
 */
async function run(intent, fromHatch) {
  const token = ++requestSeq;
  clearTimeout(slowTimer);
  setRegion(renderLoading(intent, "loading"));
  // Copy swap via timer — the request itself is never artificially delayed.
  slowTimer = setTimeout(() => {
    if (token === requestSeq) setRegion(renderLoading(intent, "slow"));
  }, SLOW_THRESHOLD_MS);

  const outcome = await authorizeIntent(intent);
  if (token !== requestSeq) return; // superseded by a newer request
  clearTimeout(slowTimer);

  if (outcome.kind === "decision") {
    clearHatchIssues();
    const sheet = renderCertificate(outcome.body);
    setRegion(sheet);
    wireCertificate(sheet, outcome.body);
    void runInPageChecks(sheet, outcome.body);
    return;
  }

  if (
    outcome.kind === "problem" &&
    fromHatch &&
    (outcome.status === 400 || outcome.status === 422)
  ) {
    // Invalid input from the hatch: the schema error renders BESIDE the raw
    // JSON editor (offending field + allowed values), never a toast. The
    // viewer region keeps its previous state.
    if (hatchIssues) hatchIssues.replaceChildren(renderInputIssues(outcome.problem));
    return;
  }

  clearHatchIssues();
  if (outcome.kind === "problem") {
    setRegion(
      renderProblemPanel({
        title: typeof outcome.problem.title === "string" ? outcome.problem.title : "Request failed",
        detail: typeof outcome.problem.detail === "string" ? outcome.problem.detail : undefined,
        status: typeof outcome.problem.status === "number" ? outcome.problem.status : outcome.status,
        type: typeof outcome.problem.type === "string" ? outcome.problem.type : undefined,
      }),
    );
  } else if (outcome.kind === "network-error") {
    setRegion(
      renderProblemPanel({
        title: "Could not reach the API",
        detail: `${outcome.message}. No request reached the engine: no decision was made and no evidence envelope exists.`,
        status: null,
      }),
    );
  } else {
    setRegion(
      renderProblemPanel({
        title: "Unexpected response",
        detail:
          "The server returned a response that is neither a decision nor a problem document. No certificate can be shown without a signed evidence envelope.",
        status: typeof outcome.status === "number" ? outcome.status : null,
      }),
    );
  }
}

function buildPicker() {
  if (!picker) return;
  for (const scenario of SCENARIOS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "scenario";
    button.dataset.scenario = scenario.id;
    button.setAttribute("aria-pressed", "false");

    const label = document.createElement("span");
    label.className = "sc-label";
    label.textContent = scenario.label;
    const note = document.createElement("span");
    note.className = "sc-note";
    note.textContent = scenario.note;
    const mono = document.createElement("span");
    mono.className = "sc-mono";
    mono.textContent = `POST /authorize · profile ${String(scenario.intent.profile)}`;
    button.append(label, note, mono);

    button.addEventListener("click", () => {
      for (const other of picker.querySelectorAll(".scenario")) {
        other.setAttribute("aria-pressed", other === button ? "true" : "false");
      }
      if (hatchInput) hatchInput.value = JSON.stringify(scenario.intent, null, 2);
      void run(scenario.intent, false);
    });
    picker.append(button);
  }
}

function wireHatch() {
  if (!hatchSend || !hatchInput) return;
  hatchSend.addEventListener("click", () => {
    let intent;
    try {
      intent = JSON.parse(hatchInput.value);
    } catch (error) {
      // Local parse failure: rendered beside the editor; no request is made.
      if (hatchIssues) {
        hatchIssues.replaceChildren(
          renderInputIssues({
            kind: "parse",
            message: error instanceof Error ? error.message : String(error),
          }),
        );
      }
      return;
    }
    clearHatchIssues();
    void run(intent, true);
  });
}

// Initial state: the ghosted empty-certificate shell (replaces the static
// markup with the canonical render so the two can never drift visually).
setRegion(renderEmptyShell());
buildPicker();
wireHatch();
