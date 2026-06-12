/**
 * TWO-LAYER decision enforcement (ET16, D6/CXT-C): credential scope ∩ rule pack,
 * most-restrictive wins.
 *
 * decideIntent() is the SINGLE decision function of the engine — POST /authorize
 * and decision replay (src/evidence/replay.ts, shared by POST /verify and the
 * offline scripts/replay.ts CLI) all run exactly this code, so the served and
 * replayed decisions can never drift (the same single-source-of-truth posture as
 * replayEnvelope/verifyEvidence).
 *
 * Semantics (pinned in docs/evaluator-semantics.md §7, versioned by
 * EVALUATOR_VERSION — 0.2.0 introduced this layer):
 *
 *   - No `agent_credential` on the intent → the rule-pack evaluation verbatim
 *     (credential-free intents behave EXACTLY as evaluator 0.1.0).
 *   - `agent_credential` present → ADMISSION first: the credential must verify
 *     (verifyAgentCredential — did:key, offline). An INVALID credential throws
 *     AgentCredentialError: that is an integration failure (4xx problem+json at
 *     the API, error ≠ deny), NEVER a decision.
 *   - A VALID credential contributes a SCOPE LAYER: allow iff the intent's
 *     merchant.mcc is in scope.allowed_mcc, else deny with AGENT_SCOPE_EXCEEDED.
 *   - Combination = most_restrictive across the two layers under the FIXED
 *     engine severity deny > review > allow. This cross-layer severity is ENGINE
 *     semantics pinned by EVALUATOR_VERSION — unlike the pack's
 *     decision_precedence, which is pack DATA governing intra-pack rule
 *     conflicts only. Since the scope layer is binary (allow/deny):
 *     pack-deny × scope-allow → deny;  pack-allow × scope-deny → deny;
 *     pack-review × scope-deny → deny; pack-review × scope-allow → review;
 *     pack-allow × scope-allow → allow.
 *
 * Pure and deterministic: no clock, no I/O, no randomness, no LLM. Ed25519
 * verification inside the admission gate is itself deterministic, so the same
 * intent bytes + pack always yield the same decision (or the same refusal).
 */
import type { Evaluation } from "../rules/evaluator.ts";
import { evaluate } from "../rules/evaluator.ts";
import type { RulePack } from "../rules/pack-schema.ts";
import { verifyAgentCredential } from "./verify.ts";

/**
 * ENGINE-level reason code (joins the closed set; not defined by any pack):
 * the presented credential is VALID but its allowed-MCC scope excludes the
 * intent's merchant.mcc. Carried by a SIGNED deny — a scope violation is a
 * decision, not an error.
 */
export const AGENT_SCOPE_EXCEEDED = "AGENT_SCOPE_EXCEEDED";

/**
 * Resolve the intent's merchant.mcc for the scope check: a plain-object
 * traversal reading OWN properties only (mirrors the evaluator's §2 field
 * resolution). Anything other than a present string reads as ABSENT.
 */
function resolveMerchantMcc(intent: Record<string, unknown>): string | undefined {
  if (!Object.hasOwn(intent, "merchant")) return undefined;
  const merchant = intent["merchant"];
  if (
    merchant === null ||
    typeof merchant !== "object" ||
    Array.isArray(merchant) ||
    !Object.hasOwn(merchant, "mcc")
  ) {
    return undefined;
  }
  const mcc = (merchant as Record<string, unknown>)["mcc"];
  return typeof mcc === "string" ? mcc : undefined;
}

/**
 * The engine's complete decision function: rule-pack evaluation plus (when an
 * agent credential is presented) the credential-scope layer, combined
 * most-restrictively.
 *
 * Throws AgentCredentialError when a presented credential fails verification —
 * the ADMISSION GATE. The caller decides the surface mapping: 4xx problem+json
 * at the API; a conclusive NOT-REPRODUCED at replay. The throw is part of the
 * deterministic contract (same bytes → same refusal), never a decision.
 */
export function decideIntent(
  intent: Record<string, unknown>,
  pack: RulePack,
): Evaluation {
  // ADMISSION GATE first: an invalid credential must refuse the intent even
  // when the rule pack alone would already deny it (error ≠ deny — a refusal
  // and a deny are different categories and must never blur).
  const credential = Object.hasOwn(intent, "agent_credential")
    ? verifyAgentCredential(intent["agent_credential"])
    : undefined;

  const packEvaluation = evaluate(intent, pack);
  if (credential === undefined) return packEvaluation;

  // SCOPE LAYER: strict membership of the intent's merchant.mcc in the
  // credential's allowed list. An ABSENT mcc never passes the screen (the same
  // missing-field rule as evaluator §3) — only reachable on non-API-validated
  // intents (e.g. replay of a foreign artifact), but it must be defined for
  // the decision to stay deterministic everywhere.
  const mcc = resolveMerchantMcc(intent);
  const scopeAllows = mcc !== undefined && credential.allowed_mcc.includes(mcc);
  if (scopeAllows) return packEvaluation;

  // most_restrictive: a scope deny beats every pack decision (deny > review >
  // allow). reason_codes stay de-duplicated (§5.4): the engine code is appended
  // after the pack's codes unless a pack rule already carried the same string.
  return {
    decision: "deny",
    reason_codes: packEvaluation.reason_codes.includes(AGENT_SCOPE_EXCEEDED)
      ? packEvaluation.reason_codes
      : [...packEvaluation.reason_codes, AGENT_SCOPE_EXCEEDED],
    // The scope layer is NOT a pack rule: its basis is the credential embedded
    // in payment_intent (covered by intent_hash), so matched_rules stays the
    // pack's matches and the scope signal travels in reason_codes.
    matched_rules: packEvaluation.matched_rules,
  };
}
