#!/usr/bin/env node
/**
 * Standalone OFFLINE decision-REPLAY CLI — the re-evaluation leg that
 * verifier/verify.mjs deliberately does NOT perform.
 *
 *   verifier/verify.mjs  → is this evidence AUTHENTIC? (signature, canonical
 *                          form, hashes). node built-ins only; never replays.
 *   scripts/replay.ts    → is the cited DECISION REPRODUCIBLE? Re-run the pure
 *                          evaluator on the cited intent + pack and compare.
 *
 * These are DIFFERENT properties. BY DEFAULT this tool answers ONLY
 * reproducibility and does NOT verify the signature — run verify.mjs for
 * authenticity. Because re-evaluation REQUIRES the evaluator, this script
 * imports src/ (the allowed direction). That is exactly why it is a separate
 * file from verify.mjs, whose node:-only independence is structural and must
 * never take a src/ import.
 *
 * OPTIONAL --jwks (combined verdict): pass --jwks to ALSO run the independent
 * verifier (verifyEvidence) over the same artifact and report authenticity
 * alongside reproducibility. The two properties stay distinct — the DEFAULT
 * still never touches the signature; --jwks is an explicit opt-in so that a
 * SINGLE exit 0 can mean "reproduced AND authentic." Without it, a bare
 * "reproduced" (exit 0) is a reproducibility verdict only and must NOT be read
 * as "valid evidence" by automation consuming the exit code. (Importing
 * verifyEvidence here does not weaken verify.mjs's independence: the verifier
 * still imports nothing from src/; only this caller depends on it.)
 *
 * It shares the very same replayEnvelope() the POST /verify route runs, so the
 * served and offline reproducibility verdicts can never disagree.
 *
 * Usage:
 *   node --experimental-strip-types scripts/replay.ts \
 *     --evidence <evidence.jws> --pack <pack.json> [--jwks <jwks.json>]
 *
 * Exit codes (mirroring verify.mjs discipline):
 *   0 = success. WITHOUT --jwks: the decision REPRODUCED. WITH --jwks: it
 *       reproduced AND the artifact is authentic.
 *   1 = a negative verdict: the decision did not re-derive (or could not be
 *       replayed here, D12), OR — with --jwks — the artifact is not authentic.
 *       With --jwks a MALFORMED envelope is in this class too: the verifier
 *       classifies those bytes as not-valid-evidence, so the combined verdict
 *       must not soften them to exit 2 (see malformedArtifact()).
 *   2 = operator/input error (bad usage, unreadable/unparseable input) —
 *       nothing was replayed or verified either way. WITHOUT --jwks this
 *       includes a malformed envelope: bare replay has no signature to consult,
 *       so "malformed" stays an input condition (the two-tools boundary).
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { canonicalize, CanonicalizationError } from "../src/crypto/canonicalize.ts";
import { replayEnvelope } from "../src/evidence/replay.ts";
import { loadRulePack } from "../src/rules/loader.ts";
import {
  isCanonicalB64url,
  validateEnvelopeShape,
  verifyEvidence,
} from "../verifier/verify.mjs";

const UNCERTIFIED_NOTE =
  "UNCERTIFIED — synthetic demo rule pack; not a fatwa / not certified / not production advice.";

function inputError(message: string): never {
  console.error(`INPUT ERROR (nothing was replayed): ${message}`);
  console.error(
    "Operator/input problem, NOT a reproducibility verdict (exit 2).",
  );
  process.exit(2);
}

/**
 * Print the authenticity-FAIL verdict (header + the first failing check). Shared
 * by the --jwks legs — the malformed-artifact guards, the pack-mismatch
 * disambiguation and the final authenticity leg — so the FAIL wording and the
 * first-failing-check format have a single definition and cannot drift between
 * the call sites.
 */
function printAuthenticityFail(auth: ReturnType<typeof verifyEvidence>): void {
  console.log("AUTHENTICITY (--jwks): FAIL — this artifact is NOT valid evidence.");
  const firstFail = auth.checks.find((check) => !check.ok);
  if (firstFail !== undefined) {
    console.log(`  first failing check: ${firstFail.title} — ${firstFail.detail}`);
  }
}

/**
 * Reject a malformed evidence artifact with the MODE-CORRECT exit code. Bare
 * replay has no signature to consult, so a malformed envelope is an operator
 * error (exit 2, "nothing was replayed"). With --jwks the combined verdict
 * imports the VERIFIER's contract, and verify.mjs classifies the same bytes as
 * a FAIL verdict (exit 1) — signature first, so a forged-then-malformed
 * artifact is named inauthentic rather than handed the softer operator-error
 * code. Exit 2 here would let exit-code automation that pages on exit 1 be
 * silenced by the cheapest possible tampering: malforming the payload.
 */
function malformedArtifact(
  detail: string,
  jws: string,
  jwks: { keys?: unknown[] } | undefined,
): never {
  if (jwks !== undefined) {
    console.log(`MALFORMED ARTIFACT: ${detail}`);
    const auth = verifyEvidence({ jws, jwks });
    if (!auth.ok) {
      printAuthenticityFail(auth);
      console.log("");
      console.log(`  ${UNCERTIFIED_NOTE}`);
      process.exit(1);
    }
    // Unreachable by construction: every caller rejects on a property the
    // verifier re-checks itself (JWS structure, segment encoding, payload
    // JSON-ness via signature/canonical-form, canonicalizability, the shared
    // strict schema). If the tools ever diverge, that is a bug in one of
    // them — an input/tooling condition to report, never a verdict.
    inputError(
      `${detail} (yet the verifier accepted the artifact — ` +
        "canonicalizer/schema divergence between the two tools, please report)",
    );
  }
  inputError(detail);
}

function main(): void {
  // parseArgs throws on an unknown flag / stray positional / a value-option given
  // with no value. Bad usage is an OPERATOR error (exit 2), never an uncaught throw
  // that Node exits 1 on — exit 1 is a verdict, and a typo'd flag is not one.
  let values;
  try {
    values = parseArgs({
      options: {
        evidence: { type: "string" },
        pack: { type: "string" },
        jwks: { type: "string" },
      },
    }).values;
  } catch (error) {
    inputError(
      `${error instanceof Error ? error.message : String(error)} — usage: ` +
        "node --experimental-strip-types scripts/replay.ts --evidence <evidence.jws> " +
        "--pack <pack.json> [--jwks <jwks.json>]",
    );
  }
  if (!values.evidence || !values.pack) {
    console.error(
      "usage: node --experimental-strip-types scripts/replay.ts " +
        "--evidence <evidence.jws> --pack <pack.json> [--jwks <jwks.json>]",
    );
    process.exit(2);
  }

  // Read the operator's input FILES. Any problem here — an unreadable evidence,
  // pack or JWKS file, or an unparseable pack/JWKS — is an OPERATOR error
  // (exit 2) in EVERY mode, never exit 1: that code is a verdict, and a missing
  // side input means nothing ran. The pack and JWKS load FIRST so the
  // evidence-ARTIFACT guards below can defer to the verifier in --jwks mode
  // (deferral needs the JWKS in hand before the first content check).
  let jws: string;
  let pack;
  let jwks: { keys?: unknown[] } | undefined;
  try {
    // Load WITHOUT enforcing the current evaluator version. A foreign-evaluator
    // pack (a genuine historical or future artifact) must be validated and hashed,
    // then handed to replayEnvelope, which classifies it as a D12 "could not be
    // attempted" verdict (reproduced:null, exit 1) — NOT rejected here as an
    // operator/input error (exit 2). The rule_pack_hash guard below still binds the
    // pack bytes to the envelope, so a wrong or tampered pack is still rejected.
    pack = loadRulePack(readFileSync(values.pack, "utf8"), {
      enforceEvaluatorVersion: false,
    });
    // --jwks is OPTIONAL; when given, an unreadable/unparseable JWKS FILE is still
    // an operator error (nothing was verified), never an authenticity verdict.
    if (values.jwks !== undefined) {
      jwks = JSON.parse(readFileSync(values.jwks, "utf8")) as { keys?: unknown[] };
    }
    jws = readFileSync(values.evidence, "utf8").trim();
  } catch (error) {
    inputError(error instanceof Error ? error.message : String(error));
  }

  // Evidence-ARTIFACT content guards. From here on a failure is a property of
  // the artifact's BYTES, not of the operator's files, so the exit code is
  // MODE-DEPENDENT — see malformedArtifact(): bare replay reads a malformed
  // artifact as an operator error (exit 2); with --jwks the verifier's FAIL
  // verdict wins (exit 1), since verify.mjs classifies every one of these as
  // not-valid-evidence and trivial malleation (e.g. appending `=` padding to a
  // segment) must not silence automation that alerts on authenticity failures.
  const parts = jws.split(".");
  if (parts.length !== 3 || parts.some((segment) => segment.length === 0)) {
    malformedArtifact("evidence is not a 3-segment JWS-compact artifact", jws, jwks);
  }
  // RFC 7515 segments are canonical, UNPADDED base64url. Node's decoder is
  // lenient (it ignores `=` padding and a final char's don't-care bits), so many
  // distinct strings decode to the same bytes. A non-canonical encoding is a
  // malformed artifact (the strict verifier rejects it too via isCanonicalB64url);
  // reject it here so bare replay can never read a non-compact JWS as "reproduced."
  if (!parts.every((segment) => isCanonicalB64url(segment))) {
    malformedArtifact(
      "evidence is not canonical base64url (RFC 7515) — the artifact is malformed",
      jws,
      jwks,
    );
  }
  const payloadB64 = parts[1] as string;
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch (error) {
    malformedArtifact(
      "evidence payload is not valid JSON — " +
        (error instanceof Error ? error.message : String(error)),
      jws,
      jwks,
    );
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    malformedArtifact("evidence payload is not a JSON object envelope", jws, jwks);
  }
  const envelope = decoded as Record<string, unknown>;

  const checkingAuthenticity = jwks !== undefined;
  console.log(
    checkingAuthenticity
      ? "OFFLINE DECISION REPLAY (+ authenticity via --jwks)"
      : "OFFLINE DECISION REPLAY — re-evaluation only, NO signature check",
  );
  console.log(`  evidence: ${values.evidence}`);
  console.log(`  pack:     ${values.pack}`);
  if (checkingAuthenticity) {
    console.log(`  jwks:     ${values.jwks}`);
    console.log("  Reproducibility AND authenticity are reported separately below;");
    console.log("  exit 0 requires BOTH to pass.");
  } else {
    console.log("  NOTE: this tool does NOT verify authenticity — run verifier/verify.mjs");
    console.log("        (or pass --jwks) for the signature/canonical-form/hash checks.");
    console.log("        Replay alone asks: does the decision re-derive from intent + pack?");
  }
  console.log("");

  // Malformed-artifact guard #1 — CANONICALIZABILITY. A non-canonicalizable
  // envelope (e.g. one carrying a lone UTF-16 surrogate, which RFC 8785
  // §3.2.2.2 requires terminating on, or one nested past the depth bound) can
  // never be valid evidence and cannot be replayed. Runs BEFORE the shape /
  // pack / authenticity branches below: canonicalizing the WHOLE envelope here
  // catches a lone surrogate in ANY field (payment_intent included), even one
  // the strict schema below treats as opaque, and on every branch
  // (replayEnvelope's D12 early return would otherwise skip the check). Never
  // an uncaught crash; the message names the actual cause rather than assuming
  // a surrogate. The exit code is MODE-DEPENDENT — see malformedArtifact():
  // bare replay exits 2 (operator error), --jwks defers to the verifier's
  // FAIL verdict (exit 1).
  try {
    canonicalize(envelope);
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      malformedArtifact(
        "the evidence envelope cannot be canonicalized per RFC 8785, so it is a " +
          `malformed artifact that cannot be replayed: ${error.message}`,
        jws,
        jwks,
      );
    }
    throw error;
  }

  // Malformed-artifact guard #2 — STRICT v0.1 ENVELOPE SHAPE. Bare replay does
  // NOT run the signature/authenticity path, so without this it has no schema
  // gate at all: a structurally-valid-JSON envelope missing required fields
  // (or with mistyped ones) slips through to replayEnvelope and either crashes on
  // canonicalize(undefined) or emits a FALSE "REPRODUCED" (exit 0) to exit-code-only
  // automation. validateEnvelopeShape is the verifier's OWN strict schema (the exact
  // check POST /verify enforces), reused here as the single source of truth so the
  // two verification tools reject the SAME malformed artifacts. A malformed envelope
  // can be neither authenticated NOR replayed; the exit code is MODE-DEPENDENT —
  // see malformedArtifact(): bare replay exits 2 (operator error), --jwks defers
  // to the verifier's FAIL verdict (exit 1) so that tampering a field's FORMAT
  // (e.g. a non-hex rule_pack_hash) cannot dodge the forgery signal the
  // pack-mismatch disambiguation below exists to give. A genuine D12
  // (foreign-evaluator) artifact still PASSES this gate: the schema pins
  // envelope_version to "0.1.0" but checks evaluator_version by semver FORMAT only,
  // so it reaches the D12 "could not be attempted" verdict below.
  const shapeError = validateEnvelopeShape(envelope);
  if (shapeError !== null) {
    malformedArtifact(
      `the evidence envelope does not conform to the v0.1 schema (${shapeError}) — ` +
        "the artifact is malformed",
      jws,
      jwks,
    );
  }

  // The cited pack must actually BE the pack the envelope references — id +
  // version AND content hash. id/version do NOT pin pack CONTENT: rule_pack_hash
  // exists precisely because two packs can share an id/version yet differ
  // byte-for-byte. A disagreement on either is normally the operator handing the
  // wrong pack — an input error (exit 2), not a verdict (mirrors the /verify
  // route's `cited.hash === rule_pack_hash` guard), never a reproducibility
  // verdict against bytes the envelope never cited.
  const packMismatch =
    pack.pack.id !== envelope["rule_pack_id"] ||
    pack.pack.version !== envelope["rule_pack_version"] ||
    pack.hash !== String(envelope["rule_pack_hash"]);

  // --jwks DISAMBIGUATION (the load-bearing fix). The cited rule_pack_* read
  // above are UNAUTHENTICATED, so a mismatch has TWO causes: (1) an AUTHENTIC
  // artifact whose operator simply supplied the wrong --pack (a real operator
  // error → exit 2 below); or (2) a FORGED artifact whose rule_pack_* were
  // tampered — which breaks the signature — and is an authenticity FAIL (exit 1),
  // NOT "supply the cited pack". Letting the exit-2 path win for case (2) would
  // misreport forged evidence as an operator/input condition (and send the
  // operator hunting for a "cited pack" that never existed). In --jwks mode the
  // signature is exactly what tells the two apart, so consult it BEFORE the exit-2
  // path: pure (no-pack) authenticity does not depend on the operator's --pack, so
  // an inauthentic artifact exits 1 here and an authentic one falls through to the
  // genuine wrong-pack operator error. Bare replay has no signature to consult and
  // keeps the operator-error reading (exit 2) — the documented two-tools boundary.
  if (jwks !== undefined && packMismatch) {
    const auth = verifyEvidence({ jws, jwks });
    if (!auth.ok) {
      printAuthenticityFail(auth);
      console.log("");
      console.log(`  ${UNCERTIFIED_NOTE}`);
      process.exit(1);
    }
    // Authentic bytes: the cited rule_pack_* are signed (genuine), so the operator
    // really did supply the wrong pack — fall through to the exit-2 checks.
  }
  if (
    pack.pack.id !== envelope["rule_pack_id"] ||
    pack.pack.version !== envelope["rule_pack_version"]
  ) {
    inputError(
      `the --pack provided is ${pack.pack.id}@${pack.pack.version}, but the ` +
        `envelope cites ${String(envelope["rule_pack_id"])}@` +
        `${String(envelope["rule_pack_version"])} — supply the cited pack`,
    );
  }
  if (pack.hash !== String(envelope["rule_pack_hash"])) {
    inputError(
      `the --pack provided hashes to ${pack.hash}, but the envelope cites ` +
        `rule_pack_hash ${String(envelope["rule_pack_hash"])} — supply the exact cited pack`,
    );
  }

  // --- Reproducibility leg (always run) ---
  // The malformed-artifact guards above (canonicalizability + strict v0.1 shape)
  // already reject a lone surrogate and any missing/mistyped field, so
  // replayEnvelope's own canonicalization of reason_codes / matched_rules should
  // not throw here. This try/catch is defensive belt-and-suspenders: the house rule
  // is that a crash is NEVER a verdict, so any CanonicalizationError that somehow
  // reaches this seam is surfaced as a clean operator error (exit 2), never an
  // uncaught exit-1 stack trace — mirroring verify.mjs's VERIFIER-ERROR wrap.
  let r: ReturnType<typeof replayEnvelope>;
  try {
    r = replayEnvelope(envelope, pack.pack);
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      inputError(
        "the evidence envelope cannot be canonicalized per RFC 8785, so it is a " +
          `malformed artifact that cannot be replayed: ${error.message}`,
      );
    }
    throw error;
  }
  const citedDecision = String(envelope["decision"]);
  let reproduced = false;
  if (!r.replayed) {
    // Pack resolved but the evaluator version is unsupported (D12): replay
    // could not be ATTEMPTED. reproduced is null (unknown), not a clean reproduce.
    console.log("RESULT: NOT REPRODUCED — replay could not be attempted.");
    console.log(`  ${r.detail}`);
    console.log(`  envelope decision: "${citedDecision}"`);
  } else if (r.reproduced) {
    reproduced = true;
    console.log(
      `RESULT: REPRODUCED — re-evaluation yields decision "${r.decision}" ` +
        `(${JSON.stringify(r.reason_codes)}), matching the envelope.`,
    );
  } else {
    console.log(
      `RESULT: NOT REPRODUCED — the envelope claims decision "${citedDecision}", ` +
        `but re-evaluation yields "${r.decision}".`,
    );
    if (r.mismatch !== undefined) {
      console.log(`  mismatch: ${r.mismatch}`);
    }
    console.log("  The artifact may be authentic yet record a decision this engine does not");
    console.log("  reproduce (e.g. tampered-then-re-signed).");
    if (!checkingAuthenticity) {
      console.log("  Authenticity is a separate question — run verifier/verify.mjs.");
    }
  }

  // --- Authenticity leg (only with --jwks) ---
  let authentic = false;
  if (jwks !== undefined) {
    // The SAME independent verifier the offline path and POST /verify run. It is
    // reported as a DISTINCT verdict — reproducibility above is unaffected.
    const auth = verifyEvidence({ jws, jwks, pack: pack.pack });
    authentic = auth.ok;
    console.log("");
    if (authentic) {
      console.log("AUTHENTICITY (--jwks): PASS — signature, canonical form and hashes verify.");
    } else {
      printAuthenticityFail(auth);
    }
  }

  console.log("");
  console.log(`  ${UNCERTIFIED_NOTE}`);

  // --- Exit ---
  if (!checkingAuthenticity) {
    if (reproduced) {
      // Loud label: a bare reproduce is NOT an authenticity verdict. Automation
      // that needs "valid evidence" must pass --jwks (or run verify.mjs).
      console.log("  NOTE: authenticity was NOT checked — this is a reproducibility verdict");
      console.log("        only. Pass --jwks (or run verifier/verify.mjs) to confirm the signature.");
      process.exit(0);
    }
    process.exit(1);
  }
  // Combined mode: exit 0 ONLY when BOTH properties hold.
  if (reproduced && authentic) {
    process.exit(0);
  }
  process.exit(1);
}

main();
