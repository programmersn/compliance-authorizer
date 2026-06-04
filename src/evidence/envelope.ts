/**
 * Evidence envelope (ET5): the signed record of one authorization decision.
 *
 * The envelope is canonicalized (RFC 8785) and signed as the JWS payload, so
 * any third party can re-derive every claim offline:
 *   - intent_hash      = sha256(JCS(payment_intent))
 *   - rule_pack_hash   = sha256(JCS(rule pack))     → fetch the pack, recompute
 *   - evaluator_version + the two hashes form the replay key (CXT-B)
 *
 * Clock and UUID are INJECTED — decisions are deterministic, envelope identity
 * fields are not, and keeping them injectable is what lets fixtures and the
 * W2 committed examples/ be byte-reproducible.
 */
import { randomUUID } from "node:crypto";
import { canonicalBytes, canonicalize } from "../crypto/canonicalize.ts";
import { sha256Hex } from "../crypto/hash.ts";
import { signCompact } from "../crypto/jws.ts";
import type { SigningKey } from "../crypto/keys.ts";
import { EVALUATOR_VERSION, type Evaluation } from "../rules/evaluator.ts";
import type { LoadedRulePack } from "../rules/loader.ts";

export const ENVELOPE_VERSION = "0.1.0";

export interface EnvelopeDeps {
  now: () => Date;
  uuid: () => string;
}

export const defaultEnvelopeDeps: EnvelopeDeps = {
  now: () => new Date(),
  uuid: randomUUID,
};

/**
 * v0.1 scholar-signature slot: a labeled UNCERTIFIED specimen, never a bare
 * null (ET20). Wording is the verbatim DX11 honesty contract; the projection
 * stays future-conditional ("would carry", never "carries").
 */
export interface ScholarSignatureRef {
  status: "uncertified";
  statement: string;
  scholar_did: null;
  signature: null;
  certification_note: string;
}

export const UNCERTIFIED_SCHOLAR_REF: ScholarSignatureRef = {
  status: "uncertified",
  statement:
    "synthetic demo rule pack — not a fatwa / not certified / not production advice",
  scholar_did: null,
  signature: null,
  certification_note:
    "a certified v1.0 pack would carry the scholar's did:key and a detached JWS over rule_pack_hash here",
};

export interface EvidenceEnvelope {
  envelope_version: string;
  decision_id: string;
  decision: Evaluation["decision"];
  reason_codes: string[];
  matched_rules: Evaluation["matched_rules"];
  rule_pack_id: string;
  rule_pack_version: string;
  rule_pack_hash: string;
  evaluator_version: string;
  intent_hash: string;
  scholar_signature_ref: ScholarSignatureRef;
  payment_intent: Record<string, unknown>;
  decision_timestamp: string;
}

export function buildEnvelope(
  intent: Record<string, unknown>,
  evaluation: Evaluation,
  loadedPack: LoadedRulePack,
  deps: EnvelopeDeps = defaultEnvelopeDeps,
): EvidenceEnvelope {
  return {
    envelope_version: ENVELOPE_VERSION,
    decision_id: `ev-${deps.uuid()}`,
    decision: evaluation.decision,
    reason_codes: evaluation.reason_codes,
    matched_rules: evaluation.matched_rules,
    rule_pack_id: loadedPack.pack.id,
    rule_pack_version: loadedPack.pack.version,
    rule_pack_hash: loadedPack.hash,
    evaluator_version: EVALUATOR_VERSION,
    intent_hash: sha256Hex(canonicalize(intent)),
    scholar_signature_ref: UNCERTIFIED_SCHOLAR_REF,
    payment_intent: intent,
    decision_timestamp: deps.now().toISOString(),
  };
}

/** Sign the canonical envelope bytes into the JWS-compact evidence artifact. */
export function signEnvelope(
  envelope: EvidenceEnvelope,
  key: SigningKey,
): string {
  return signCompact(canonicalBytes(envelope), key);
}
