/**
 * GET /rule-packs/:id/:version HTTP contract (W2):
 *   - a HIT serves the pack's EXACT RFC 8785 canonical bytes, so a consumer can
 *     recompute the published rule_pack_hash straight from the raw response body
 *     (content-addressing: sha256(rawBody) === loaded.hash);
 *   - a MISS is an INTEGRATION FAILURE — RFC 9457 problem+json 404, never an
 *     empty 200 and never anything signed (error ≠ deny).
 *
 * Route-isolated: the route plugin is registered on a FRESH Fastify instance
 * (not via buildServer), so this file never imports sibling route modules and
 * stays parallel-safe.
 */
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { canonicalize } from "../../src/crypto/canonicalize.ts";
import { sha256Hex } from "../../src/crypto/hash.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { rulePacksRoute } from "../../src/routes/rule-packs.ts";
import { PROBLEM_CONTENT_TYPE, registerProblemHandling } from "../../src/http/problem.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loaded = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
);

const app = Fastify();
registerProblemHandling(app);
void app.register(rulePacksRoute, {
  packsByIdVersion: new Map([[`${loaded.pack.id}/${loaded.pack.version}`, loaded]]),
});
const ready = app.ready();

afterAll(() => app.close());

describe("GET /rule-packs/:id/:version serves the exact content-addressed bytes", () => {
  it("HIT → 200 and sha256(rawResponseBody) === the published rule_pack_hash", async () => {
    await ready;
    const response = await app.inject({
      method: "GET",
      url: "/rule-packs/shariah/0.1.1",
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");

    // The load-bearing guarantee: a consumer who hashes the RAW response bytes
    // gets the SAME hash carried in every envelope decided against this pack.
    // This only holds if the canonical STRING was sent verbatim — an object
    // re-serialized by fast-json-stringify would reorder keys and break it.
    const rawHash = createHash("sha256")
      .update(response.rawPayload)
      .digest("hex");
    expect(rawHash).toBe(loaded.hash);

    // And the bytes parse back to the same pack: re-canonicalizing the parsed
    // body reproduces the hash too (proves it is well-formed canonical JSON,
    // not merely some byte string that happens to hash correctly).
    const parsed = JSON.parse(response.body) as unknown;
    expect(sha256Hex(canonicalize(parsed))).toBe(loaded.hash);

    // Content-addressed ⇒ immutable ⇒ cacheable for a year.
    expect(response.headers["cache-control"]).toBe(
      "public, max-age=31536000, immutable",
    );
  });

  it("MISS on unknown version → 404 problem+json, NO decision artifacts", async () => {
    await ready;
    const response = await app.inject({
      method: "GET",
      url: "/rule-packs/shariah/9.9.9",
    });

    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(404);
    expect(body["type"]).toContain("/rule-pack-not-found");
    // A failure is not a decision: nothing signed, nothing decided.
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
  });

  it("MISS on unknown id → 404 problem+json", async () => {
    await ready;
    const response = await app.inject({
      method: "GET",
      url: "/rule-packs/esg/0.1.0",
    });

    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
    const body = response.json<Record<string, unknown>>();
    expect(body["status"]).toBe(404);
    expect(body).not.toHaveProperty("evidence_artifact");
    expect(body).not.toHaveProperty("decision");
  });
});
