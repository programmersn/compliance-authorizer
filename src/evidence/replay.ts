/**
 * Decision REPLAY (CXT-B) — the re-evaluation leg the offline verifier
 * deliberately does NOT perform.
 *
 * W1 / verifier/verify.mjs proves an envelope is AUTHENTIC (the signature
 * covers these exact payload bytes, the canonical form is correct, the hashes
 * recompute). It says nothing about whether the cited DECISION is the one the
 * pure evaluator actually produces for the cited intent. Those are two
 * DIFFERENT properties:
 *
 *   - valid       : the artifact is cryptographically authentic (verify.mjs).
 *   - reproduced  : re-running evaluate(payment_intent, pack) under the cited
 *                   evaluator_version yields the SAME decision/reason_codes/
 *                   matched_rules that the envelope records.
 *
 * An envelope can be valid:true yet reproduced:false — e.g. its decision was
 * overwritten to "allow" and then RE-SIGNED (authentic bytes, dishonest claim),
 * or it pins an evaluator_version this engine does not run (D12: it cannot be
 * faithfully replayed here, so reproduced is null, not false).
 *
 * This module is the SINGLE source of replay truth, shared verbatim by the
 * POST /verify route and the offline scripts/replay.ts CLI — the server surface
 * and the offline path can never disagree on reproducibility because they run
 * one function (mirroring how the route reuses verifyEvidence). Importing src/
 * here is correct: re-evaluation is a server-side capability and REQUIRES the
 * evaluator. This is NOT verifier/verify.mjs — that file stays node:-only and
 * never replays.
 *
 * Pure and deterministic: no clock, no I/O, no randomness.
 */
import { canonicalize } from "../crypto/canonicalize.ts";
import { EVALUATOR_VERSION, evaluate } from "../rules/evaluator.ts";
import type { RulePack } from "../rules/pack-schema.ts";

/**
 * The replay outcome attached to a verification result. The four shapes are
 * mutually exclusive and ordered by how far replay could proceed:
 *
 *   1. pack not resolved      → replayed:false, reproduced:null
 *   2. evaluator unsupported  → replayed:false, reproduced:null  (D12)
 *   3. pack + evaluator OK     → replayed:true,  reproduced:boolean
 *
 * reproduced is `null` (not false) whenever replay could not be ATTEMPTED:
 * "unknown", not "mismatch". Only a completed re-evaluation yields a boolean.
 */
export type Reproducibility =
  | {
      rule_pack_resolved: false;
      replayed: false;
      reproduced: null;
      detail: string;
    }
  | {
      rule_pack_resolved: true;
      evaluator_version_supported: false;
      replayed: false;
      reproduced: null;
      detail: string;
    }
  | {
      rule_pack_resolved: true;
      evaluator_version_supported: true;
      replayed: true;
      reproduced: boolean;
      decision: string;
      reason_codes: string[];
      matched_rules: unknown[];
      mismatch?: string;
    };

/** Stable, order-sensitive structural equality via RFC 8785 canonical form. */
function canonicalEqual(a: unknown, b: unknown): boolean {
  return canonicalize(a) === canonicalize(b);
}

/**
 * Re-evaluate the intent the envelope cites against the resolved pack and
 * compare the recomputed decision to the one the envelope records.
 *
 * @param envelope  the AUTHENTIC envelope recovered by verifyEvidence (caller
 *   must only invoke replay on an authentic artifact — an inauthentic one has
 *   envelope:null and must not be replayed).
 * @param pack      the LoadedRulePack the envelope cites, or undefined if this
 *   engine does not serve it.
 */
export function replayEnvelope(
  envelope: Record<string, unknown>,
  pack: RulePack | undefined,
): Reproducibility {
  if (pack === undefined) {
    const id = String(envelope["rule_pack_id"]);
    const version = String(envelope["rule_pack_version"]);
    return {
      rule_pack_resolved: false,
      replayed: false,
      reproduced: null,
      detail:
        `cited rule pack ${id}@${version} is not served by this engine — ` +
        `fetch it (GET /rule-packs/:id/:version) and replay offline`,
    };
  }

  // D12 surfaced at the verify layer: this engine runs exactly one evaluator
  // semantics version. An envelope pinning a different one cannot be faithfully
  // replayed here — reproduced is UNKNOWN (null), never a false "mismatch".
  const pinnedEvaluator = String(envelope["evaluator_version"]);
  if (pinnedEvaluator !== EVALUATOR_VERSION) {
    return {
      rule_pack_resolved: true,
      evaluator_version_supported: false,
      replayed: false,
      reproduced: null,
      detail:
        `this engine runs evaluator ${EVALUATOR_VERSION}; the envelope pins ` +
        `evaluator ${pinnedEvaluator} (D12) — it cannot be faithfully replayed here`,
    };
  }

  const intent = envelope["payment_intent"] as Record<string, unknown>;
  const replay = evaluate(intent, pack);

  const decisionMatch = replay.decision === envelope["decision"];
  const reasonCodesMatch = canonicalEqual(
    replay.reason_codes,
    envelope["reason_codes"],
  );
  const matchedRulesMatch = canonicalEqual(
    replay.matched_rules,
    envelope["matched_rules"],
  );
  const reproduced = decisionMatch && reasonCodesMatch && matchedRulesMatch;

  // A concise, specific diff so a valid-but-not-reproduced verdict says WHICH
  // claim the re-evaluation contradicts (the crown-jewel signal).
  let mismatch: string | undefined;
  if (!reproduced) {
    const parts: string[] = [];
    if (!decisionMatch) {
      parts.push(
        `decision: envelope claims ${JSON.stringify(envelope["decision"])}, ` +
          `re-evaluation yields ${JSON.stringify(replay.decision)}`,
      );
    }
    if (!reasonCodesMatch) {
      parts.push(
        `reason_codes: envelope ${JSON.stringify(envelope["reason_codes"])}, ` +
          `re-evaluation ${JSON.stringify(replay.reason_codes)}`,
      );
    }
    if (!matchedRulesMatch) {
      parts.push("matched_rules differ from the re-evaluation");
    }
    mismatch = parts.join("; ");
  }

  return {
    rule_pack_resolved: true,
    evaluator_version_supported: true,
    replayed: true,
    reproduced,
    decision: replay.decision,
    reason_codes: replay.reason_codes,
    matched_rules: replay.matched_rules,
    ...(mismatch !== undefined ? { mismatch } : {}),
  };
}
