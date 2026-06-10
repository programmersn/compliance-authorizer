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
 *   2 = operator/input error (bad usage, unreadable/unparseable input) —
 *       nothing was replayed or verified either way.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { CanonicalizationError } from "../src/crypto/canonicalize.ts";
import { replayEnvelope } from "../src/evidence/replay.ts";
import { loadRulePack } from "../src/rules/loader.ts";
import { verifyEvidence } from "../verifier/verify.mjs";

const UNCERTIFIED_NOTE =
  "UNCERTIFIED — synthetic demo rule pack; not a fatwa / not certified / not production advice.";

function inputError(message: string): never {
  console.error(`INPUT ERROR (nothing was replayed): ${message}`);
  console.error(
    "Operator/input problem, NOT a reproducibility verdict (exit 2).",
  );
  process.exit(2);
}

function main(): void {
  const { values } = parseArgs({
    options: {
      evidence: { type: "string" },
      pack: { type: "string" },
      jwks: { type: "string" },
    },
  });
  if (!values.evidence || !values.pack) {
    console.error(
      "usage: node --experimental-strip-types scripts/replay.ts " +
        "--evidence <evidence.jws> --pack <pack.json> [--jwks <jwks.json>]",
    );
    process.exit(2);
  }

  // Read + decode. Any file/parse problem is an OPERATOR error (exit 2), never
  // exit 1 — that code is a verdict, and an unreadable file means nothing ran.
  let jws: string;
  let envelope: Record<string, unknown>;
  let pack;
  let jwks: { keys?: unknown[] } | undefined;
  try {
    jws = readFileSync(values.evidence, "utf8").trim();
    const parts = jws.split(".");
    if (parts.length !== 3 || parts.some((segment) => segment.length === 0)) {
      inputError("evidence is not a 3-segment JWS-compact artifact");
    }
    const payloadB64 = parts[1] as string;
    const decoded: unknown = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    );
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
      inputError("evidence payload is not a JSON object envelope");
    }
    envelope = decoded as Record<string, unknown>;
    // Load WITHOUT enforcing the current evaluator version. A foreign-evaluator
    // pack (a genuine historical or future artifact) must be validated and hashed,
    // then handed to replayEnvelope, which classifies it as a D12 "could not be
    // attempted" verdict (reproduced:null, exit 1) — NOT rejected here as an
    // operator/input error (exit 2). The rule_pack_hash guard below still binds the
    // pack bytes to the envelope, so a wrong or tampered pack is still rejected.
    pack = loadRulePack(readFileSync(values.pack, "utf8"), {
      enforceEvaluatorVersion: false,
    });
    // --jwks is OPTIONAL; when given, an unreadable/unparseable JWKS is still an
    // operator error (nothing was verified), never an authenticity verdict.
    if (values.jwks !== undefined) {
      jwks = JSON.parse(readFileSync(values.jwks, "utf8")) as { keys?: unknown[] };
    }
  } catch (error) {
    inputError(error instanceof Error ? error.message : String(error));
  }

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

  // The cited pack must actually BE the pack the envelope references — id +
  // version AND content hash. id/version do NOT pin pack CONTENT: rule_pack_hash
  // exists precisely because two packs can share an id/version yet differ
  // byte-for-byte. A disagreement on either is the operator handing the wrong
  // pack — an input error, not a verdict (mirrors the /verify route's
  // `cited.hash === rule_pack_hash` guard), so the wrong pack is always exit 2,
  // never a reproducibility verdict against bytes the envelope never cited.
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
  // replayEnvelope canonicalizes the envelope's reason_codes / matched_rules to
  // compare them, and RFC 8785 §3.2.2.2 now makes canonicalize() THROW on invalid
  // Unicode (a lone surrogate). A malformed envelope must surface as a clean
  // operator error (exit 2, "nothing was replayed"), never an uncaught crash —
  // the same never-crash discipline verify.mjs enforces at its canonical-form
  // step. Bare replay does not authenticate, so such an envelope can reach here
  // even with a spoofed (pack-matching) rule_pack_hash.
  let r: ReturnType<typeof replayEnvelope>;
  try {
    r = replayEnvelope(envelope, pack.pack);
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      inputError(
        "the evidence envelope contains invalid Unicode (a lone UTF-16 surrogate) " +
          "that cannot be canonicalized per RFC 8785 §3.2.2.2 — the artifact is malformed",
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
      console.log("AUTHENTICITY (--jwks): FAIL — this artifact is NOT valid evidence.");
      const firstFail = auth.checks.find((check) => !check.ok);
      if (firstFail !== undefined) {
        console.log(`  first failing check: ${firstFail.title} — ${firstFail.detail}`);
      }
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
