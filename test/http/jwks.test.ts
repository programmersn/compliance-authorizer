/**
 * GET /.well-known/jwks.json HTTP contract (W2):
 *   - a READ endpoint: 200-only, no integration-failure branch of its own;
 *   - publishes EVERY historical public key (offline verification by kid across
 *     key rotation), each with RFC 7638 thumbprint integrity (kid === thumbprint);
 *   - serves PUBLIC keys ONLY — the private `d` field never reaches the wire,
 *     enforced STRUCTURALLY by the response schema's allowlist.
 *
 * Route-isolated: registers ONLY jwksRoute on a fresh Fastify() instance, so this
 * file imports no sibling route module and is safe to run while siblings are
 * mid-edit. No registerProblemHandling() — this plugin has no 4xx surface.
 */
import Fastify from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import {
  computeKid,
  exportPrivateJwk,
  generateSigningKey,
} from "../../src/crypto/keys.ts";
import { jwksRoute } from "../../src/routes/jwks.ts";

// TWO independently-generated keys prove the document carries "all historical
// keys", not just the current signer.
const k1 = generateSigningKey();
const k2 = generateSigningKey();

const app = Fastify();
void app.register(jwksRoute, {
  publishedKeys: [k1.publicJwk, k2.publicJwk],
});

afterAll(() => app.close());

describe("GET /.well-known/jwks.json publishes every historical public key", () => {
  it("returns 200 with both keys and a shared-cache header", async () => {
    await app.ready();
    const response = await app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/json");
    // We emit Cache-Control, so we verify it.
    expect(response.headers["cache-control"]).toBe("public, max-age=300");

    const body = response.json<{ keys: Record<string, unknown>[] }>();
    expect(body.keys).toHaveLength(2);

    // BOTH kids are present — order-independent.
    const publishedKids = body.keys.map((k) => k["kid"]);
    expect(publishedKids).toContain(k1.kid);
    expect(publishedKids).toContain(k2.kid);
  });

  it("every published key is a well-formed Ed25519 OKP signing JWK with kid === RFC 7638 thumbprint", async () => {
    await app.ready();
    const response = await app.inject({
      method: "GET",
      url: "/.well-known/jwks.json",
    });
    const body = response.json<{ keys: Record<string, unknown>[] }>();

    for (const key of body.keys) {
      expect(key["kty"]).toBe("OKP");
      expect(key["crv"]).toBe("Ed25519");
      expect(key["alg"]).toBe("EdDSA");
      expect(key["use"]).toBe("sig");
      expect(typeof key["x"]).toBe("string");
      // kid integrity: the published kid is the RFC 7638 thumbprint of `x`.
      expect(computeKid(key["x"] as string)).toBe(key["kid"]);
      // Never expose a private key: no `d` member on any published JWK.
      expect(key).not.toHaveProperty("d");
    }
  });
});

describe("the private `d` field is stripped at the serialization boundary (runtime no-leak guard)", () => {
  // The assertion above is necessary but not sufficient on its own: publicJwk has
  // no `d` to begin with, so "no d" passes vacuously. This test feeds a PrivateJwk
  // (which DOES carry `d`) through the route and proves the response schema's
  // allowlist drops it on the wire. Remove `additionalProperties: false` from the
  // route's JwkSchema and this test correctly FAILS.
  it("a PrivateJwk handed in as a published key is served WITHOUT its `d`", async () => {
    const leaky = exportPrivateJwk(k1); // PrivateJwk extends PublicJwk → carries `d`
    expect(leaky).toHaveProperty("d"); // sanity: the input really does leak

    const leakApp = Fastify();
    // PrivateJwk is structurally a PublicJwk plus `d`, so it is assignable to the
    // route's publishedKeys without a cast — exactly the mistake the guard defends.
    void leakApp.register(jwksRoute, { publishedKeys: [leaky] });
    try {
      await leakApp.ready();
      const response = await leakApp.inject({
        method: "GET",
        url: "/.well-known/jwks.json",
      });

      expect(response.statusCode).toBe(200);
      const body = response.json<{ keys: Record<string, unknown>[] }>();
      expect(body.keys).toHaveLength(1);
      expect(body.keys[0]).not.toHaveProperty("d");
      // The public material still came through intact.
      expect(body.keys[0]?.["kid"]).toBe(k1.kid);
    } finally {
      await leakApp.close();
    }
  });
});
