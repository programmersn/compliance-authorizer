/**
 * POST /authorize HTTP contract (ET6 + DT1 + DX9):
 *   - a DECISION — including DENY — is HTTP 200 with a signed envelope;
 *   - an INTEGRATION FAILURE is RFC 9457 problem+json and carries NO envelope,
 *     no decision, nothing signed. The two are structurally distinct.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { buildJwks, generateSigningKey } from "../../src/crypto/keys.ts";
import { verifyCompact } from "../../src/crypto/jws.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { buildServer } from "../../src/server.ts";
import { PROBLEM_CONTENT_TYPE } from "../../src/http/problem.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = generateSigningKey();

const app = buildServer({
  loadedPacks: [loadedPack],
  signingKey,
  envelopeDeps: {
    now: () => new Date("2026-06-04T12:00:00.000Z"),
    uuid: () => "11111111-2222-4333-8444-555555555555",
  },
});

afterAll(() => app.close());

const validIntent = {
  profile: "shariah-v0.1",
  merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
  amount: { value: 420, currency: "EUR" },
};

describe("decisions are ALWAYS 200 — read the body, not the status (DT1)", () => {
  it("DENY is HTTP 200 with a verifiable signed envelope", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: validIntent,
    });

    expect(response.statusCode).toBe(200); // ← a deny is a DECISION, not an error
    expect(response.headers["content-type"]).toContain("application/json");

    const body = response.json<Record<string, unknown>>();
    expect(body["decision"]).toBe("deny");
    expect(body["reason_codes"]).toEqual(["MAYSIR"]);
    expect(body["rule_pack_hash"]).toBe(loadedPack.hash);
    expect(body["decision_id"]).toBe("ev-11111111-2222-4333-8444-555555555555");
    expect(body["decision_timestamp"]).toBe("2026-06-04T12:00:00.000Z");

    // The evidence artifact verifies and matches the response surface.
    const verified = verifyCompact(
      body["evidence_artifact"] as string,
      buildJwks([signingKey.publicJwk]),
    );
    const envelope = verified.payload as Record<string, unknown>;
    expect(envelope["decision"]).toBe("deny");
    expect(envelope["intent_hash"]).toBe(body["intent_hash"]);
    expect(envelope["scholar_signature_ref"]).toMatchObject({
      status: "uncertified",
      statement:
        "synthetic demo rule pack — not a fatwa / not certified / not production advice",
    });
  });

  it("ALLOW is HTTP 200", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        profile: "shariah-v0.1",
        merchant: { name: "seaside-hotel", mcc: "7011", attributes: [] },
        amount: { value: 180, currency: "EUR" },
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ decision: string }>().decision).toBe("allow");
  });

  it("REVIEW is HTTP 200 (mixed-revenue ETF scenario)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        profile: "shariah-v0.1",
        merchant: { name: "mixed-revenue-etf", mcc: "6211", attributes: [] },
        amount: { value: 1000, currency: "USD" },
        screening: { mixed_revenue_ratio: 0.12 },
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json<{ decision: string; reason_codes: string[] }>();
    expect(body.decision).toBe("review");
    expect(body.reason_codes).toEqual(["MIXED_REVENUE"]);
  });
});

describe("integration failures are problem+json and NEVER signed (error ≠ deny)", () => {
  it("malformed intent (missing merchant) → 400 problem+json, NO envelope, NO decision", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { profile: "shariah-v0.1", amount: { value: 10, currency: "EUR" } },
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(400);
    expect(Array.isArray(body["issues"])).toBe(true);
    // The load-bearing assertions: a failure carries NO decision artifacts.
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
    expect(body["detail"]).toContain("no evidence envelope");
  });

  it("numeric mcc → 400 (no type coercion on a compliance API)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        ...validIntent,
        merchant: { ...validIntent.merchant, mcc: 7011 },
      },
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  it("unknown extra field → 400 (no silent stripping)", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { ...validIntent, override_decision: "allow" },
    });
    expect(response.statusCode).toBe(400);
    const body = response.json<Record<string, unknown>>();
    expect(body).not.toHaveProperty("evidence_artifact");
  });

  it("unknown profile → 422 problem+json listing available profiles, NO envelope", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: { ...validIntent, profile: "esg-v9.9" },
    });

    expect(response.statusCode).toBe(422);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

    const body = response.json<Record<string, unknown>>();
    expect(body["available_profiles"]).toEqual(["shariah-v0.1"]);
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
  });

  it("unknown route → 404 problem+json", async () => {
    const response = await app.inject({ method: "GET", url: "/nope" });
    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });
});
