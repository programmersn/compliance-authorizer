// @vitest-environment happy-dom
/**
 * The six playground interaction states (DESIGN.md §6 / T-D2) and the decision
 * certificate's field rank + honesty pattern (DESIGN.md §5 / T-D1), as REAL
 * code paths over the pure render functions.
 *
 * The highest-risk separation (error ≠ deny) is asserted STRUCTURALLY:
 * a problem+json render must not produce a certificate node and must not
 * contain the UNCERTIFIED certificate band.
 */
import { describe, expect, it } from "vitest";
import {
  REASON_LABELS,
  renderCertificate,
  renderEmptyShell,
  renderInputIssues,
  renderLoading,
  renderProblemPanel,
  type DomNodeLike,
} from "../../web/js/render.js";
import { SCENARIOS, intentSummary } from "../../web/js/scenarios.js";

const DOCUMENT_POSITION_FOLLOWING = 4;

function must(node: DomNodeLike | null): DomNodeLike {
  expect(node).not.toBeNull();
  return node as DomNodeLike;
}

function fakeJws(kid: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", kid })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ note: "render fixture" })).toString("base64url");
  return `${header}.${payload}.c2lnbmF0dXJl`;
}

/** Mirrors the REAL /authorize response shape (confirmed by execution against the shipped pack). */
const DENY_BODY = {
  decision: "deny",
  reason_codes: ["MAYSIR"],
  matched_rules: [
    {
      rule_id: "MAYSIR-ATTR",
      reason_code: "MAYSIR",
      decision: "deny",
      title: "Gambling exposure in merchant attributes",
      description:
        "Merchant attribute data flags gambling activity (e.g. a casino operation inside a hotel). Maysir (gambling) is prohibited even when the primary merchant category is permissible.",
      standards_ref: { status: "pending", note: "pending — populated on v1.0 certification" },
    },
  ],
  decision_id: "ev-00000000-0000-4000-8000-000000000000",
  decision_timestamp: "2026-01-01T00:00:00.000Z",
  rule_pack_id: "shariah",
  rule_pack_version: "0.1.1",
  rule_pack_hash: "5573ec7e039e8f882a5a8d253f901dbb29951442bace5a42353be5da50522ab4",
  rule_pack_status: "uncertified",
  evaluator_version: "0.2.0",
  intent_hash: "a".repeat(64),
  envelope_version: "0.1.0",
  evidence_artifact: fakeJws("kid-render-fixture"),
};

const REVIEW_BODY = {
  ...DENY_BODY,
  decision: "review",
  reason_codes: ["MIXED_REVENUE"],
  matched_rules: [
    {
      rule_id: "MIXED-REVENUE",
      reason_code: "MIXED_REVENUE",
      decision: "review",
      title: "Mixed impermissible revenue share above demo threshold",
      description:
        "Screening data reports an impermissible revenue share at or above the synthetic demo threshold of 5%. The threshold is illustrative, not a certified screening standard; the case is routed to human review.",
      standards_ref: { status: "pending", note: "pending — populated on v1.0 certification" },
    },
  ],
};

const ALLOW_BODY = {
  ...DENY_BODY,
  decision: "allow",
  reason_codes: [],
  matched_rules: [],
};

const CASINO_INTENT = {
  profile: "shariah-v0.1",
  merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
  amount: { value: 420, currency: "EUR" },
};

describe("scenario picker data (T-D2) — exactly the three locked generic scenarios", () => {
  it("ships casino-hotel, mixed-revenue ETF, and subscription — generic labels only", () => {
    expect(SCENARIOS.map((scenario) => scenario.id)).toEqual([
      "casino-hotel",
      "mixed-revenue-etf",
      "subscription",
    ]);
    expect(SCENARIOS.map((scenario) => scenario.label)).toEqual([
      "Agent books a casino-hotel",
      "Agent rebalances a mixed-revenue ETF",
      "Agent sets up a subscription",
    ]);
    // every intent targets the shipped profile; synthetic data only
    for (const scenario of SCENARIOS) {
      expect(scenario.intent.profile).toBe("shariah-v0.1");
    }
  });

  it("intentSummary keeps the request visible in one line", () => {
    expect(intentSummary(CASINO_INTENT)).toBe(
      "casino-hotel · MCC 7011 · 420 EUR · profile shariah-v0.1",
    );
    expect(intentSummary({})).toBe("(unnamed merchant)");
  });
});

describe("state 1 — initial: empty certificate shell (never a blank panel)", () => {
  it("renders a ghosted shell with the call-to-action and the UNCERTIFIED band", () => {
    const shell = renderEmptyShell();
    expect(shell.classList.contains("sheet--empty")).toBe(true);
    expect(shell.textContent).toContain("Pick a scenario to see a signed decision.");
    // UNCERTIFIED is unavoidable from the very first paint.
    expect(shell.textContent).toContain("Uncertified — synthetic demo rule pack");
    // Ghost outline, not a live decision.
    expect(shell.querySelector(".ghost-glyph")).not.toBeNull();
    expect(shell.querySelector(".decision")).toBeNull();
  });
});

describe("states 2 + 3 — loading, then the >2s slow copy swap", () => {
  it("loading keeps the intent summary visible with a step indicator", () => {
    const node = renderLoading(CASINO_INTENT, "loading");
    expect(node.textContent).toContain("Authorizing intent…");
    expect(node.textContent).toContain("casino-hotel · MCC 7011 · 420 EUR · profile shariah-v0.1");
    expect([...node.querySelectorAll(".steps-mini li")].length).toBe(3);
  });

  it("slow swaps the copy but the request summary STAYS visible", () => {
    const node = renderLoading(CASINO_INTENT, "slow");
    expect(node.textContent).toContain("Still waiting for the API…");
    expect(node.textContent).toContain("casino-hotel · MCC 7011");
    expect(node.textContent).toContain("nothing was lost");
  });
});

describe("state 4 — success: the decision certificate (DESIGN.md §5 field rank)", () => {
  const sheet = renderCertificate(DENY_BODY);

  it("DENY renders the inked decision block with reason + plain-language line", () => {
    expect(sheet.dataset["decision"]).toBe("deny");
    expect(must(sheet.querySelector(".dlabel")).textContent).toBe("DENY");
    expect(must(sheet.querySelector(".dreason")).textContent).toBe("MAYSIR — gambling");
    expect(must(sheet.querySelector(".dexpl")).textContent).toContain("Maysir (gambling) is prohibited");
  });

  it("the honesty pattern is complete: band + chip + watermark + projection (amber, never dismissible)", () => {
    expect(must(sheet.querySelector(".uncert-inner b")).textContent).toBe(
      "Uncertified — synthetic demo rule pack",
    );
    expect(must(sheet.querySelector(".uncert-inner span")).textContent).toBe(
      "Not a fatwa · not certified · not production advice",
    );
    expect(must(sheet.querySelector(".chip")).textContent).toBe("Uncertified");
    expect(sheet.querySelector(".watermark")).not.toBeNull();
    // forward projection — future-conditional copy
    expect(must(sheet.querySelector(".project-line")).textContent).toContain(
      "populate on certification",
    );
  });

  it("basis table cites the matched rule and the AAOIFI slot is a STYLED pending placeholder", () => {
    const basis = must(sheet.querySelector(".basis"));
    expect(basis.textContent).toContain("MAYSIR-ATTR");
    expect(basis.textContent).toContain("Gambling exposure in merchant attributes");
    const pending = must(basis.querySelector("td.pending"));
    expect(pending.textContent).toBe("pending — populated on v1.0 certification");
  });

  it("carries the full replay key: pack id+version, pack hash, evaluator, intent hash", () => {
    const basis = must(sheet.querySelector(".basis"));
    expect(basis.textContent).toContain("shariah · version 0.1.1");
    expect(basis.textContent).toContain(`sha256:${DENY_BODY.rule_pack_hash}`);
    expect(basis.textContent).toContain("deterministic — no LLM in the decision path");
    expect(basis.textContent).toContain(`sha256:${DENY_BODY.intent_hash}`);
  });

  it("the Maqasid line is explicitly illustrative, never computed analysis", () => {
    const maqasid = must(sheet.querySelector(".maqasid"));
    expect(maqasid.textContent).toContain("Maqasid (illustrative):");
    expect(maqasid.textContent).toContain("illustrative mapping, not computed at v0.1");
  });

  it("the madhab notice names all four schools with the locked v0.1-Hanafi sentence", () => {
    const madhab = must(sheet.querySelector(".madhab"));
    expect(madhab.textContent).toContain("Hanafi · Maliki · Shafiʿi · Hanbali.");
    expect(madhab.textContent).toContain("v0.1 encodes the Hanafi position");
    expect(madhab.textContent).toContain(
      "A certified version would state coverage per your committee's madhab",
    );
  });

  it("the verify affordance sits at the BOTTOM with command, statuses, fingerprint, download", () => {
    const verify = must(sheet.querySelector(".verify"));
    expect(verify.textContent).toContain("Verify this yourself — trust nothing on our server");
    expect(must(verify.querySelector(".cmd-text")).textContent).toContain(
      `node verifier/verify.mjs --evidence ${DENY_BODY.decision_id}.jws`,
    );
    expect(verify.querySelector('[data-check="signature"]')).not.toBeNull();
    expect(verify.querySelector('[data-check="pack-hash"]')).not.toBeNull();
    // replay is NEVER claimed in-page — it stays an offline instruction
    const replay = must(verify.querySelector('[data-check="replay"]'));
    expect(replay.dataset["state"]).toBe("na");
    expect(replay.textContent).toContain("npm run replay");
    expect(verify.textContent).toContain("issuer key kid kid-render-fixture");
    expect(verify.querySelector('[data-action="download-envelope"]')).not.toBeNull();
  });

  it("field rank is the locked order: band → decision → basis → madhab → verify", () => {
    const band = must(sheet.querySelector(".uncert"));
    const decision = must(sheet.querySelector(".decision"));
    const basis = must(sheet.querySelector(".basis"));
    const madhab = must(sheet.querySelector(".madhab"));
    const verify = must(sheet.querySelector(".verify"));
    const ordered = [band, decision, basis, madhab, verify];
    for (let i = 0; i < ordered.length - 1; i += 1) {
      const earlier = ordered[i] as DomNodeLike;
      const later = ordered[i + 1] as DomNodeLike;
      expect(
        earlier.compareDocumentPosition(later) & DOCUMENT_POSITION_FOLLOWING,
        `element ${String(i + 1)} must follow element ${String(i)}`,
      ).toBe(DOCUMENT_POSITION_FOLLOWING);
    }
  });

  it("REVIEW gets first-class amber treatment, not a grey could-not-decide", () => {
    const review = renderCertificate(REVIEW_BODY);
    expect(review.dataset["decision"]).toBe("review");
    expect(must(review.querySelector(".dlabel")).textContent).toBe("REVIEW");
    expect(must(review.querySelector(".dreason")).textContent).toBe(
      "MIXED_REVENUE — mixed impermissible revenue",
    );
    expect(must(review.querySelector(".dexpl")).textContent).toContain("routed to human review");
  });

  it("ALLOW renders, and the AAOIFI placeholder row is still present (never blank)", () => {
    const allow = renderCertificate(ALLOW_BODY);
    expect(allow.dataset["decision"]).toBe("allow");
    expect(must(allow.querySelector(".dlabel")).textContent).toBe("ALLOW");
    expect(must(allow.querySelector(".dreason")).textContent).toContain("no prohibition matched");
    const pending = must(allow.querySelector("td.pending"));
    expect(pending.textContent).toBe("pending — populated on v1.0 certification");
    expect(allow.textContent).toContain("(no rule matched)");
  });

  it("refuses to render a certificate without a signed evidence artifact (error ≠ deny)", () => {
    expect(() => renderCertificate({ ...DENY_BODY, evidence_artifact: "" })).toThrow(
      /without a signed evidence artifact/,
    );
  });

  it("the reason-code label map is closed over the shipped pack's codes", () => {
    expect(Object.keys(REASON_LABELS).sort()).toEqual([
      "GHARAR",
      "INTOXICANTS",
      "MAYSIR",
      "MIXED_REVENUE",
      "RIBA",
    ]);
  });
});

describe("state 5 — API error: a DASHED problem panel, structurally NOT a certificate", () => {
  const problem = renderProblemPanel({
    title: "Unknown compliance profile",
    detail:
      'Profile "esg-v9.9" is not loaded on this engine. No decision was made and no evidence envelope exists for this request.',
    status: 422,
    type: "https://github.com/programmersn/compliance-authorizer/problems/unknown-profile",
  });

  it("renders the problem+json detail in a problem panel", () => {
    expect(problem.classList.contains("problem-panel")).toBe(true);
    expect(problem.dataset["kind"]).toBe("problem");
    expect(problem.textContent).toContain("SYSTEM ERROR — NOT A DECISION");
    expect(problem.textContent).toContain("Unknown compliance profile");
    expect(problem.textContent).toContain("no evidence envelope exists");
    expect(problem.textContent).toContain("HTTP 422 · application/problem+json");
  });

  it("MUST NOT produce a certificate node nor the UNCERTIFIED certificate band", () => {
    // the structural split is the primary separation; color is secondary
    expect(problem.classList.contains("sheet")).toBe(false);
    expect(problem.querySelector(".sheet")).toBeNull();
    expect(problem.querySelector(".uncert")).toBeNull();
    expect(problem.querySelector(".chip")).toBeNull();
    expect(problem.querySelector(".decision")).toBeNull();
    expect(problem.textContent).not.toContain("Uncertified — synthetic demo rule pack");
    expect(problem.textContent).not.toContain("Evidence Record");
  });

  it("a network failure (no HTTP response) renders honestly", () => {
    const offline = renderProblemPanel({
      title: "Could not reach the API",
      detail: "fetch failed. No request reached the engine.",
      status: null,
    });
    expect(offline.textContent).toContain("no HTTP response");
    expect(offline.querySelector(".uncert")).toBeNull();
  });
});

describe("state 6 — invalid input: schema errors render BESIDE the hatch editor", () => {
  it("shows the offending field, message, and allowed values from problem+json issues", () => {
    const node = renderInputIssues({
      detail: "The request body failed schema validation.",
      issues: [
        { field: "/merchant/mcc", message: 'must match pattern "^[0-9]{4}$"' },
        { field: "/profile", message: "must be equal to one of the allowed values", allowed_values: ["shariah-v0.1"] },
      ],
    });
    expect(node.dataset["kind"]).toBe("input-problem");
    expect(node.textContent).toContain("/merchant/mcc");
    expect(node.textContent).toContain('must match pattern "^[0-9]{4}$"');
    expect(node.textContent).toContain("allowed values: shariah-v0.1");
    // the hatch stays labeled advanced / unsupported
    expect(node.textContent).toContain("advanced / unsupported");
    // and it is NOT a certificate either
    expect(node.querySelector(".uncert")).toBeNull();
    expect(node.textContent).not.toContain("Uncertified — synthetic demo rule pack");
  });

  it("a local JSON parse failure renders without any request having been made", () => {
    const node = renderInputIssues({ kind: "parse", message: "Unexpected token } in JSON" });
    expect(node.textContent).toContain("Not valid JSON");
    expect(node.textContent).toContain("Unexpected token");
  });

  it("falls back to the problem detail when no issues array exists", () => {
    const node = renderInputIssues({ detail: "The request body failed schema validation." });
    expect(node.textContent).toContain("The request body failed schema validation.");
  });
});
