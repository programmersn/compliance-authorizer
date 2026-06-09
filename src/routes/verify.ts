/**
 * POST /verify — server-side convenience wrapper over the SAME offline verifier
 * that anyone can run with zero server trust (W2).
 *
 *   - An INAUTHENTIC-but-well-formed artifact is a verification RESULT
 *     (HTTP 200 { valid: false }), NOT a 4xx — "signature invalid" is the same
 *     category as "deny", a finding, never an integration failure. Only a
 *     MALFORMED request (bad body shape) is 4xx problem+json.
 *   - The decision is NOT re-run here; verify.mjs deliberately does not replay
 *     the evaluator. This route only re-checks the cryptographic evidence.
 *
 * The cross-tree import below is LOAD-BEARING in the barrier: it proves at
 * `tsc` + `eslint` time that src/ can resolve the offline verifier
 * (verifier/verify.mjs) BEFORE the fan-out depends on it. The forbidden
 * direction is verify.mjs → src/; this src/ → verify.mjs direction is allowed.
 *
 * SHARED VERIFIER: this route REUSES verifyEvidence from verifier/verify.mjs —
 * the exact same code path the standalone CLI runs — so the signature, canonical
 * form and hash verdicts can never diverge from the offline path. The ONE
 * deliberate exception is the D12 evaluator_version seam: `verify.mjs --pack`
 * folds it into authenticity (a mismatch → FAIL), whereas this route reclassifies
 * it as REPRODUCIBILITY (authentic bytes, reproduced:null) per the d12Only note
 * below. That divergence is intentional and surfaced, never silent.
 */
import { Type } from "@sinclair/typebox";
import type { FastifyPluginAsync } from "fastify";
import type { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { verifyEvidence } from "../../verifier/verify.mjs";
import { buildJwks } from "../crypto/keys.ts";
import type { PublicJwk } from "../crypto/keys.ts";
import { UNCERTIFIED_SCHOLAR_REF } from "../evidence/envelope.ts";
import { replayEnvelope } from "../evidence/replay.ts";
import type { LoadedRulePack } from "../rules/loader.ts";

/**
 * Request body (D10: TypeBox is the schema source of truth). Strict by design:
 * a missing/empty/non-string evidence_artifact or any unknown extra field is an
 * INTEGRATION FAILURE → 400 problem+json via the normal AJV path. This is the
 * only 4xx this route produces; a well-formed request is ALWAYS a 200 result.
 */
export const VerifyRequestSchema = Type.Object(
  {
    /** A JWS-compact evidence artifact, exactly as emitted by /authorize. */
    evidence_artifact: Type.String({ minLength: 1 }),
  },
  { additionalProperties: false },
);

export interface VerifyRouteOptions {
  publishedKeys: readonly PublicJwk[];
  packsByIdVersion: ReadonlyMap<string, LoadedRulePack>;
}

export const verifyRoute: FastifyPluginAsync<VerifyRouteOptions> = (
  app,
  options,
) => {
  // NOTE: no `response` schema is attached on purpose. fast-json-stringify
  // serializes a 200 response against its schema and SILENTLY strips any
  // undeclared field — that would drop `checks`, a null `issuer`, and the
  // Stage-3 `reproducibility` object a later stage adds. Letting Fastify
  // serialize the plain object keeps that seam open with zero schema edits.
  app.withTypeProvider<TypeBoxTypeProvider>().post(
    "/verify",
    { schema: { body: VerifyRequestSchema } },
    (request) => {
      const { evidence_artifact } = request.body;

      // Mirror the offline CLI exactly: build the JWKS from the published keys,
      // verify once WITHOUT the pack to learn which pack the envelope cites,
      // then (only if a real envelope came back) re-verify WITH that pack so
      // rule_pack_hash + id/version integrity are checked.
      const jwks = buildJwks(options.publishedKeys);
      const first = verifyEvidence({ jws: evidence_artifact, jwks });

      const env = first.envelope;
      const cited = env
        ? options.packsByIdVersion.get(
            `${String(env["rule_pack_id"])}/${String(env["rule_pack_version"])}`,
          )
        : undefined;
      const withPack = cited
        ? verifyEvidence({ jws: evidence_artifact, jwks, pack: cited.pack })
        : first;

      // REPLAY SEAM (Stage 3): authenticity and REPRODUCIBILITY are DIFFERENT
      // properties. We re-run the pure evaluator on the cited intent + pack and
      // confirm it yields the SAME decision the envelope records — the leg
      // verify.mjs deliberately skips. Replay is keyed off the NO-PACK pass:
      // `first.envelope` recovers a trustworthy intent whenever the signature,
      // canonical form and intent_hash all hold, INDEPENDENT of whether the
      // cited pack resolves here or the D12 evaluator_version seam lines up.
      // replayEnvelope() itself encodes the pack-not-served and D12 states. The
      // shared replayEnvelope() is the same function scripts/replay.ts runs, so
      // the served and offline reproducibility verdicts can never diverge.
      const reproducibility =
        first.ok && env ? replayEnvelope(env, cited?.pack) : undefined;

      // AUTHENTICITY must EXCLUDE the D12 evaluator_version seam. verify.mjs,
      // WHEN HANDED THE PACK, folds `pack.required_evaluator_version ===
      // envelope.evaluator_version` into `ok` (its pack-hash check). But a D12
      // mismatch is a REPRODUCIBILITY fact, not an authenticity one — an
      // envelope re-signed against an evaluator this engine does not run is
      // still cryptographically authentic (same category boundary as error ≠
      // deny). So we take authenticity from `withPack` (which also pins
      // rule_pack_hash + id/version integrity → a tampered hash stays
      // valid:false) EXCEPT in the one case where the SOLE pack-bound failure is
      // that D12 seam; there we fall back to the pack-free pass `first`.
      //
      // CRITICAL narrowing: `evaluator_version_supported === false` proves D12
      // mismatched but NOT that D12 was the only pack failure. verify.mjs check 8
      // short-circuits hash → id/version → D12, while replayEnvelope() flags D12
      // without ever inspecting the hash. So an artifact tampered on BOTH the
      // rule_pack_hash AND evaluator_version (then re-signed) would fail withPack
      // at the HASH sub-check yet still report D12 — falling back to `first`
      // would declare a hash-mismatched envelope authentic (valid:true on
      // tampered evidence — the worst failure mode). We therefore additionally
      // require the cited pack's genuine hash to MATCH the envelope's
      // rule_pack_hash. `cited.hash` is the precomputed sha256 of the canonical
      // pack on LoadedRulePack — no canonicalize/sha256 duplication, no coupling
      // to verify.mjs's message text. Only then is the D12 seam truly the lone
      // pack-bound failure. The `=== false` narrowing is type-safe: only the
      // evaluator-unsupported variant carries that field.
      const d12Only =
        reproducibility?.rule_pack_resolved === true &&
        reproducibility.evaluator_version_supported === false &&
        cited?.hash === String(env?.["rule_pack_hash"]);
      const authentic = d12Only ? first : withPack;

      // Replay is reported only alongside an AUTHENTIC verdict: an inauthentic
      // artifact carries no trustworthy intent to stand behind, so its
      // reproducibility stays absent (undefined is omitted by serialization).
      const envelope = authentic.envelope;
      const reproducibilityOut = authentic.ok ? reproducibility : undefined;

      return {
        // valid:true  == cryptographically authentic evidence.
        // valid:false == well-formed request, INAUTHENTIC artifact (bad
        //   signature, tampered payload, alg != EdDSA, kid != thumbprint, or —
        //   ONLY WHEN the cited pack resolves on this engine (rule_pack_resolved
        //   :true) — a rule_pack_hash / id-version mismatch). A D12
        //   evaluator_version mismatch is NOT inauthentic — it is reported under
        //   reproducibility. For a cited pack this engine does NOT serve, the
        //   verdict is authentic-bytes-only (signature + canonical form +
        //   intent_hash) with rule_pack_resolved:false as the honest caveat — the
        //   offline verifier behaves identically when run without --pack, and a
        //   forged unserved id can only DOWNGRADE the replay signal to
        //   reproduced:null, never forge a valid:true on served-pack tampering.
        //   STILL HTTP 200 — a verdict, never a 4xx.
        valid: authentic.ok,
        checks: authentic.checks,
        // `issuer` is recovered at the key-resolution check, which runs BEFORE
        // the signature check — so on an INAUTHENTIC artifact it would name a key
        // that did not actually sign these bytes (a claimed-not-verified identity).
        // Surface it only alongside an authentic verdict; the offline CLI hides it
        // identically (it prints the issuer block only inside `result.ok`).
        issuer: authentic.ok ? authentic.issuer : null,
        decision: envelope ? envelope["decision"] : null,
        rule_pack_id: envelope ? envelope["rule_pack_id"] : null,
        rule_pack_version: envelope ? envelope["rule_pack_version"] : null,
        // Whether the cited pack was found on THIS engine and folded into the
        // verdict (the rule_pack_hash / D12 checks). False when no envelope was
        // recovered, or its cited id/version is not loaded here.
        rule_pack_resolved: Boolean(cited),
        // REPRODUCIBILITY — distinct from `valid`. Present only on an authentic
        // artifact; `undefined` is omitted by JSON serialization, so an
        // inauthentic verdict simply carries no reproducibility object (there is
        // no trustworthy intent to replay). reproduced:true == the pure
        // evaluator re-derives the SAME decision; reproduced:false == authentic
        // bytes but a decision the engine does not reproduce (tampered-then-
        // re-signed); reproduced:null == replay could not be attempted (pack not
        // served, or a D12 evaluator-version mismatch).
        reproducibility: reproducibilityOut,
        // UNCERTIFIED is unavoidable on every served surface — true even when
        // valid:false. Reuse the envelope's honesty statement so wording can
        // never drift from the verbatim contract.
        uncertified: true,
        disclaimer: UNCERTIFIED_SCHOLAR_REF.statement,
        certification_note:
          "a certified version would additionally carry a scholar signature over rule_pack_hash",
      };
    },
  );
  return Promise.resolve();
};
