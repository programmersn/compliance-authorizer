/**
 * GET /rule-packs/:id/:version — the published rule pack's EXACT canonical
 * bytes (W2).
 *
 * Indexed by the `${id}/${version}` key so a consumer can fetch the exact pack
 * a given envelope was decided against. The response body is the pack's RFC 8785
 * canonical STRING verbatim, so a consumer can recompute the published
 * `rule_pack_hash` by hashing the raw response bytes:
 *
 *   sha256_hex(rawResponseBody) === envelope.rule_pack_hash
 *
 * This is why the canonical string is sent as-is — re-serializing the parsed
 * object (via fast-json-stringify or a response schema) would reorder keys and
 * break that byte equality. Packs are content-addressed by hash and therefore
 * immutable, so the response is cacheable for a year.
 *
 * A MISS (unknown id or version) is an INTEGRATION FAILURE: RFC 9457
 * problem+json 404 — never an empty 200, never a signed anything (error ≠ deny).
 */
import { Type } from "@sinclair/typebox";
import type { FastifyPluginAsync } from "fastify";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import type { LoadedRulePack } from "../rules/loader.ts";
import { PROBLEM_TYPE_BASE, ProblemError } from "../http/problem.ts";

/**
 * Path params only — there is deliberately NO `response` schema on this route:
 * the body is the pack's canonical string sent verbatim, and a response schema
 * would push it back through fast-json-stringify, reordering keys and breaking
 * the `sha256(rawBody) === rule_pack_hash` content-addressing guarantee.
 */
const RulePackParamsSchema = Type.Object(
  {
    id: Type.String({ minLength: 1 }),
    version: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);

export const rulePacksRoute: FastifyPluginAsync<{
  packsByIdVersion: ReadonlyMap<string, LoadedRulePack>;
}> = (app, options) => {
  app.withTypeProvider<TypeBoxTypeProvider>().get(
    "/rule-packs/:id/:version",
    { schema: { params: RulePackParamsSchema } },
    (request, reply) => {
      const { id, version } = request.params;

      const loadedPack = options.packsByIdVersion.get(`${id}/${version}`);
      if (!loadedPack) {
        // Integration failure, NOT a decision: unknown pack → 404 problem+json.
        throw new ProblemError(
          404,
          "Rule pack not found",
          `No rule pack ${id}@${version} is served by this engine.`,
          `${PROBLEM_TYPE_BASE}/rule-pack-not-found`,
        );
      }

      // Serve the EXACT canonical bytes (an RFC 8785 canonical STRING) so the
      // consumer can recompute rule_pack_hash from the raw response body. Packs
      // are immutable (content-addressed by hash) — cache hard.
      void reply
        .header("cache-control", "public, max-age=31536000, immutable")
        .type("application/json")
        .send(loadedPack.canonical);
      return reply;
    },
  );
  return Promise.resolve();
};
