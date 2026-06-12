/**
 * The playground's outcome classification — the CLIENT half of error ≠ deny:
 * only a 200 carrying a signed evidence_artifact may become a certificate;
 * problem+json stays a problem; anything else is "unexpected", never a decision.
 */
import { describe, expect, it } from "vitest";
import { authorizeIntent, classifyOutcome, SLOW_THRESHOLD_MS } from "../../web/js/api.js";

const DECISION_BODY = {
  decision: "deny",
  reason_codes: ["MAYSIR"],
  evidence_artifact: "eyJhbGciOiJFZERTQSJ9.e30.c2ln",
};

describe("classifyOutcome", () => {
  it("200 + decision + signed artifact → decision", () => {
    const outcome = classifyOutcome(200, "application/json; charset=utf-8", DECISION_BODY);
    expect(outcome.kind).toBe("decision");
  });

  it("200 WITHOUT an evidence artifact is NEVER a decision (no envelope, no certificate)", () => {
    const withoutArtifact = { decision: "deny", reason_codes: ["MAYSIR"] };
    expect(classifyOutcome(200, "application/json", withoutArtifact).kind).toBe("unexpected");
    expect(
      classifyOutcome(200, "application/json", { ...DECISION_BODY, evidence_artifact: "" }).kind,
    ).toBe("unexpected");
  });

  it("200 with a non-decision verdict string is not a decision", () => {
    expect(
      classifyOutcome(200, "application/json", { ...DECISION_BODY, decision: "approved" }).kind,
    ).toBe("unexpected");
  });

  it("4xx problem+json → problem (carrying the document)", () => {
    const problem = {
      type: "about:blank",
      title: "Request body failed schema validation",
      status: 400,
      detail: "No decision was made and no evidence envelope exists for this request.",
      issues: [{ field: "/merchant/mcc", message: 'must match pattern "^[0-9]{4}$"' }],
    };
    const outcome = classifyOutcome(400, "application/problem+json; charset=utf-8", problem);
    expect(outcome.kind).toBe("problem");
    if (outcome.kind === "problem") {
      expect(outcome.status).toBe(400);
      expect(outcome.problem["title"]).toBe("Request body failed schema validation");
    }
  });

  it("5xx problem+json → problem; non-problem bodies → unexpected", () => {
    expect(
      classifyOutcome(500, "application/problem+json", { title: "Internal error", status: 500 })
        .kind,
    ).toBe("problem");
    expect(classifyOutcome(502, "text/html", "<html>bad gateway</html>").kind).toBe("unexpected");
    expect(classifyOutcome(404, "application/json", { message: "nope" }).kind).toBe("unexpected");
  });
});

describe("authorizeIntent", () => {
  const jsonResponse = (status: number, contentType: string, body: unknown) => ({
    status,
    headers: { get: (name: string) => (name.toLowerCase() === "content-type" ? contentType : null) },
    json: () => Promise.resolve(body),
  });

  it("POSTs the intent to /authorize and returns the classified outcome", async () => {
    const calls: { url: string; init: unknown }[] = [];
    const outcome = await authorizeIntent(
      { profile: "shariah-v0.1" },
      {
        fetchImpl: (url, init) => {
          calls.push({ url, init });
          return Promise.resolve(jsonResponse(200, "application/json", DECISION_BODY));
        },
      },
    );
    expect(outcome.kind).toBe("decision");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("/authorize");
    const init = calls[0]?.init as { method: string; headers: Record<string, string>; body: string };
    expect(init.method).toBe("POST");
    expect(init.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(init.body)).toEqual({ profile: "shariah-v0.1" });
  });

  it("a rejected fetch becomes a network-error outcome (no HTTP response)", async () => {
    const outcome = await authorizeIntent(
      {},
      { fetchImpl: () => Promise.reject(new Error("connection refused")) },
    );
    expect(outcome.kind).toBe("network-error");
    if (outcome.kind === "network-error") {
      expect(outcome.message).toContain("connection refused");
    }
  });

  it("an unparseable body never crashes — classified as unexpected", async () => {
    const outcome = await authorizeIntent(
      {},
      {
        fetchImpl: () =>
          Promise.resolve({
            status: 200,
            headers: { get: () => "application/json" },
            json: () => Promise.reject(new Error("invalid json")),
          }),
      },
    );
    expect(outcome.kind).toBe("unexpected");
  });

  it("the slow-copy threshold is 2s (DESIGN.md §6 — a swap via timer, no artificial delay)", () => {
    expect(SLOW_THRESHOLD_MS).toBe(2000);
  });
});
