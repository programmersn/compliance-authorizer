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
  type EvidenceEnvelope,
} from "../evidence/envelope.ts";
import { CanonicalizationError } from "../crypto/canonicalize.ts";
import type { SigningKey } from "../crypto/keys.ts";
import type { Evaluation, MatchedRule } from "../rules/evaluator.ts";
import type { LoadedRulePack } from "../rules/loader.ts";
import { PROBLEM_TYPE_BASE, ProblemError } from "../http/problem.ts";
import type { EvidenceStore } from "../store/evidence-store.ts";
import { decideIntent } from "../vc/enforce.ts";
import { AgentCredentialError } from "../vc/verify.ts";

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
    /**
     * OPTIONAL synthetic agent credential (ET16): a JWS-compact string whose
     * did:key issuer and allowed-MCC scope are verified by src/vc/verify.ts —
     * the schema only gates "non-empty string" so an invalid credential gets
     * the dedicated 422 problem+json below, not a generic schema 400. Because
     * the credential travels INSIDE payment_intent, intent_hash covers it and
     * replay re-verifies it offline (did:key needs no key distribution).
     */
    agent_credential: Type.Optional(Type.String({ minLength: 1 })),
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
  /**
   * OPTIONAL evidence store (ET14). When present, every ISSUED decision is
   * persisted AFTER signing and BEFORE the body is returned. Absent, the route
   * is stateless and behaves identically — storage is observational, never part
   * of the decision. A persist FAILURE fails the request closed (see the hook
   * below): no signed envelope reaches the caller alongside a storage error.
   */
  store?: EvidenceStore;
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

      // The engine's SINGLE decision function (two-layer: rule pack ∩ optional
      // agent-credential scope, most-restrictive). decideIntent is the same
      // code replay runs, so served and replayed decisions can never drift.
      let evaluation: Evaluation;
      try {
        evaluation = decideIntent(intent, loadedPack.pack);
      } catch (error) {
        if (error instanceof AgentCredentialError) {
          // ADMISSION FAILURE, not a decision (error ≠ deny): a malformed,
          // tampered, alg-confused, or otherwise INVALID credential is an
          // integration failure → 422 problem+json, NEVER a signed envelope.
          // (A VALID credential whose scope excludes the MCC is the opposite
          // category: a SIGNED deny via AGENT_SCOPE_EXCEEDED.)
          throw new ProblemError(
            422,
            "Invalid agent credential",
            `The payment intent presents an agent credential that failed verification: ${error.message}. ` +
              "No decision was made and no evidence envelope exists for this request.",
            `${PROBLEM_TYPE_BASE}/invalid-agent-credential`,
            { credential_error: error.code },
          );
        }
        throw error;
      }
      let envelope: EvidenceEnvelope;
      let evidenceArtifact: string;
      try {
        envelope = buildEnvelope(
          intent,
          evaluation,
          loadedPack,
          options.envelopeDeps,
        );
        evidenceArtifact = signEnvelope(envelope, options.signingKey);
      } catch (error) {
        if (error instanceof CanonicalizationError) {
          // Invalid Unicode in the intent (e.g. a lone UTF-16 surrogate) cannot
          // be canonicalized — RFC 8785 §3.2.2.2 requires the canonicalizer to
          // terminate. This is a MALFORMED REQUEST (400 problem+json), NOT a
          // decision: no envelope is produced (error ≠ deny). AJV cannot catch
          // it upstream — a lone surrogate is syntactically valid JSON and
          // satisfies Type.String().
          throw new ProblemError(
            400,
            "Intent contains invalid Unicode",
            "The payment intent contains invalid Unicode (a lone UTF-16 surrogate) that cannot be canonicalized per RFC 8785 §3.2.2.2. No decision was made and no evidence envelope exists for this request.",
            `${PROBLEM_TYPE_BASE}/invalid-unicode`,
          );
        }
        throw error;
      }

      // error ≠ deny at the STORAGE boundary (ET14). Persist the issued decision
      // AFTER signing and BEFORE returning the body, so a write failure fails the
      // request CLOSED — a signed envelope must NEVER reach the caller alongside a
      // storage error. A thrown store error becomes a 500 problem+json (no
      // envelope, no decision in the body), exactly like every other integration
      // failure. Storage is observational: it cannot change `envelope`/the JWS
      // bytes, only whether the request succeeds. With no store wired this hook is
      // skipped and the route is stateless. (A duplicate decision_id — astronomically
      // unlikely with a v4 UUID — surfaces here as a UNIQUE-constraint throw and is
      // treated the same: fail closed, never serve a half-persisted decision.)
      if (options.store) {
        let persistResult: unknown;
        try {
          persistResult = options.store.persist({
            decision_id: envelope.decision_id,
            decision: envelope.decision,
            reason_codes: envelope.reason_codes,
            rule_pack_id: envelope.rule_pack_id,
            rule_pack_version: envelope.rule_pack_version,
            rule_pack_hash: envelope.rule_pack_hash,
            evaluator_version: envelope.evaluator_version,
            intent_hash: envelope.intent_hash,
            envelope_version: envelope.envelope_version,
            decision_timestamp: envelope.decision_timestamp,
            evidence_artifact: evidenceArtifact,
          });
        } catch (error) {
          // Fail closed: surface a generic 500 problem+json and let nothing
          // signed escape. We deliberately do NOT include the freshly-signed
          // envelope anywhere in this branch.
          request.log.error(error, "evidence store persist failed");
          throw new ProblemError(
            500,
            "Internal error",
            "A decision was computed but could not be persisted to the evidence store, so the request fails closed: no evidence envelope is returned for this request.",
            "about:blank",
          );
        }
        // The EvidenceStore port is SYNCHRONOUS by contract (store/evidence-store.ts):
        // the fail-closed boundary depends on persist() completing INLINE before we
        // return the signed body. TypeScript's `void` return type would nonetheless
        // accept an async persist() (Promise<void> is assignable to void) — and its
        // rejection would escape AFTER this 200, silently breaching the boundary
        // (the synchronous try/catch above cannot catch a rejected promise). A
        // returned thenable therefore means the wired store violated the contract:
        // fail CLOSED (a misconfiguration, never a decision), never serve a signed
        // envelope whose durable persistence we could not confirm.
        if (
          persistResult !== null &&
          (typeof persistResult === "object" || typeof persistResult === "function") &&
          typeof (persistResult as { then?: unknown }).then === "function"
        ) {
          request.log.error(
            "evidence store persist() returned a thenable; the EvidenceStore port is synchronous by contract",
          );
          throw new ProblemError(
            500,
            "Internal error",
            "A decision was computed but the evidence store is misconfigured (its persist() is not synchronous), so the request fails closed: no evidence envelope is returned for this request.",
            "about:blank",
          );
        }
      }

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
