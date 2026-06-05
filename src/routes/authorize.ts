/**
 * POST /authorize (ET6) — the always-200 decision contract (DT1):
 *
 *   - A DECISION is HTTP 200. A DENY IS 200 — read body.decision, never the
 *     status code. deny = halt, do not retry; review = halt, escalate to a
 *     human.
 *   - 400/422 are INTEGRATION FAILURES (malformed intent / unknown profile):
 *     RFC 9457 problem+json, never a signed envelope (DX9).
 */
import { Type, type Static } from "@sinclair/typebox";
import type { FastifyPluginAsync } from "fastify";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import {
  buildEnvelope,
  signEnvelope,
  type EnvelopeDeps,
} from "../evidence/envelope.ts";
import type { SigningKey } from "../crypto/keys.ts";
import { evaluate, type MatchedRule } from "../rules/evaluator.ts";
import type { LoadedRulePack } from "../rules/loader.ts";
import { PROBLEM_TYPE_BASE, ProblemError } from "../http/problem.ts";

/**
 * Synthetic payment intent (D10: TypeBox is the schema source of truth).
 * Strict by design: unknown fields are rejected (400), nothing is coerced —
 * a compliance decision must never be made on silently-repaired input.
 */
export const PaymentIntentSchema = Type.Object(
  {
    profile: Type.String({ minLength: 1 }),
    merchant: Type.Object(
      {
        name: Type.String({ minLength: 1 }),
        mcc: Type.String({ pattern: "^[0-9]{4}$" }),
        country: Type.Optional(Type.String({ pattern: "^[A-Z]{2}$" })),
        attributes: Type.Optional(Type.Array(Type.String({ minLength: 1 }))),
      },
      { additionalProperties: false },
    ),
    amount: Type.Object(
      {
        value: Type.Number({ minimum: 0 }),
        currency: Type.String({ pattern: "^[A-Z]{3}$" }),
      },
      { additionalProperties: false },
    ),
    recurring: Type.Optional(Type.Boolean()),
    screening: Type.Optional(
      Type.Object(
        {
          instrument: Type.Optional(Type.String({ minLength: 1 })),
          mixed_revenue_ratio: Type.Optional(
            Type.Number({ minimum: 0, maximum: 1 }),
          ),
        },
        { additionalProperties: false },
      ),
    ),
  },
  { additionalProperties: false },
);
export type PaymentIntent = Static<typeof PaymentIntentSchema>;

const MatchedRuleSchema = Type.Object({
  rule_id: Type.String(),
  reason_code: Type.String(),
  decision: Type.Union([Type.Literal("deny"), Type.Literal("review")]),
  title: Type.String(),
  description: Type.String(),
  standards_ref: Type.Object({
    status: Type.Literal("pending"),
    note: Type.String(),
  }),
});

/**
 * D10 drift guard (compile-time only): this response schema and the
 * evaluator's MatchedRule are hand-authored in two places and MUST stay
 * structurally identical in both directions — fast-json-stringify serializes
 * against the schema, so a field added to MatchedRule but not here would be
 * SILENTLY stripped from the API response. A mismatch fails `npm run typecheck`.
 */
type AssertTrue<T extends true> = T;
export type MatchedRuleSchemaCoversEvaluator = AssertTrue<
  Static<typeof MatchedRuleSchema> extends MatchedRule ? true : false
>;
export type EvaluatorCoversMatchedRuleSchema = AssertTrue<
  MatchedRule extends Static<typeof MatchedRuleSchema> ? true : false
>;

export const AuthorizeResponseSchema = Type.Object({
  decision: Type.Union([
    Type.Literal("allow"),
    Type.Literal("review"),
    Type.Literal("deny"),
  ]),
  reason_codes: Type.Array(Type.String()),
  matched_rules: Type.Array(MatchedRuleSchema),
  decision_id: Type.String(),
  decision_timestamp: Type.String(),
  rule_pack_id: Type.String(),
  rule_pack_version: Type.String(),
  rule_pack_hash: Type.String(),
  /** Pack certification status — the UNCERTIFIED honesty marker, visible without decoding the JWS. */
  rule_pack_status: Type.Literal("uncertified"),
  evaluator_version: Type.String(),
  intent_hash: Type.String(),
  /** Version of the signed envelope's own schema (mirrored from the envelope). */
  envelope_version: Type.String(),
  /** JWS-compact evidence envelope — verify it offline with verifier/verify.mjs. */
  evidence_artifact: Type.String(),
});

export interface AuthorizeRouteOptions {
  packsByProfile: ReadonlyMap<string, LoadedRulePack>;
  signingKey: SigningKey;
  envelopeDeps?: EnvelopeDeps;
}

export const authorizeRoute: FastifyPluginAsync<AuthorizeRouteOptions> = (
  app,
  options,
) => {
  app.withTypeProvider<TypeBoxTypeProvider>().post(
    "/authorize",
    {
      schema: {
        body: PaymentIntentSchema,
        response: { 200: AuthorizeResponseSchema },
      },
    },
    (request) => {
      const intent = request.body;

      const loadedPack = options.packsByProfile.get(intent.profile);
      if (!loadedPack) {
        // Integration failure, NOT a decision: unknown profile → 422 problem+json.
        throw new ProblemError(
          422,
          "Unknown compliance profile",
          `Profile "${intent.profile}" is not loaded on this engine. No decision was made and no evidence envelope exists for this request.`,
          `${PROBLEM_TYPE_BASE}/unknown-profile`,
          { available_profiles: [...options.packsByProfile.keys()] },
        );
      }

      const evaluation = evaluate(intent, loadedPack.pack);
      const envelope = buildEnvelope(
        intent,
        evaluation,
        loadedPack,
        options.envelopeDeps,
      );
      const evidenceArtifact = signEnvelope(envelope, options.signingKey);

      // A decision — ANY decision, including deny — is HTTP 200.
      return {
        decision: envelope.decision,
        reason_codes: envelope.reason_codes,
        matched_rules: envelope.matched_rules,
        decision_id: envelope.decision_id,
        decision_timestamp: envelope.decision_timestamp,
        rule_pack_id: envelope.rule_pack_id,
        rule_pack_version: envelope.rule_pack_version,
        rule_pack_hash: envelope.rule_pack_hash,
        rule_pack_status: loadedPack.pack.status,
        evaluator_version: envelope.evaluator_version,
        intent_hash: envelope.intent_hash,
        envelope_version: envelope.envelope_version,
        evidence_artifact: evidenceArtifact,
      };
    },
  );
  return Promise.resolve();
};
