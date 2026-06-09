/**
 * GET /.well-known/jwks.json (W2) — the issuer's public verifying keys (RFC 7517).
 *
 * Publishes the FULL set of historical public keys so any envelope ever signed
 * by this engine stays offline-verifiable by `kid`, even across key rotation.
 *
 * This is a READ endpoint: 200-only. It has no request body and no path/query
 * params, so it has NO integration-failure (4xx) branch of its own — a bad path
 * under `.well-known` is the app-level 404 handler's job, not this plugin's.
 * (error ≠ deny still holds trivially: there is no decision and nothing signed.)
 *
 * PUBLIC keys ONLY. The response schema's `additionalProperties: false` makes
 * the no-private-`d` guarantee STRUCTURAL at the serialization boundary: even if
 * a `PrivateJwk` (which carries `d`) were handed in as a `PublicJwk`,
 * fast-json-stringify emits only the allowlisted members and drops `d` on the
 * wire. That is a runtime defense, not merely a compile-time one.
 */
import { Type, type Static } from "@sinclair/typebox";
import type { FastifyPluginAsync } from "fastify";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { buildJwks, type PublicJwk } from "../crypto/keys.ts";

/** A single RFC 7517 JWK for an Ed25519 OKP public verifying key. */
const JwkSchema = Type.Object(
  {
    kty: Type.Literal("OKP"),
    crv: Type.Literal("Ed25519"),
    x: Type.String(),
    kid: Type.String(),
    alg: Type.Literal("EdDSA"),
    use: Type.Literal("sig"),
  },
  // No `d`, no extra members ever reach the wire — the runtime no-leak guard.
  { additionalProperties: false },
);

const JwksResponseSchema = Type.Object({ keys: Type.Array(JwkSchema) });

/**
 * Drift guard (compile-time only): JwkSchema and the PublicJwk interface are
 * authored in two places and MUST stay structurally identical in BOTH
 * directions — fast-json-stringify serializes against the schema, so a member
 * added to PublicJwk but not here would be SILENTLY stripped from the JWKS
 * response, and a member here but not on PublicJwk would be a phantom field.
 * A mismatch fails `npm run typecheck`. (Mirrors the authorize route's guard.)
 */
type AssertTrue<T extends true> = T;
export type JwkSchemaCoversPublicJwk = AssertTrue<
  Static<typeof JwkSchema> extends PublicJwk ? true : false
>;
export type PublicJwkCoversJwkSchema = AssertTrue<
  PublicJwk extends Static<typeof JwkSchema> ? true : false
>;

export const jwksRoute: FastifyPluginAsync<{
  publishedKeys: readonly PublicJwk[];
}> = (app, options) => {
  app.withTypeProvider<TypeBoxTypeProvider>().get(
    // The path `/.well-known/jwks.json` is a STATIC route — the dots are literal.
    "/.well-known/jwks.json",
    { schema: { response: { 200: JwksResponseSchema } } },
    (_request, reply) => {
      // RFC 7517 media type is application/jwk-set+json; application/json is
      // acceptable and is what Fastify serializes here. The JWKS is a public,
      // slowly-rotating document, so a short shared cache is safe and friendly.
      reply.header("cache-control", "public, max-age=300");
      return buildJwks(options.publishedKeys);
    },
  );
  return Promise.resolve();
};
