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
 * These are DIFFERENT properties. This tool answers ONLY reproducibility and
 * does NOT verify the signature — run verify.mjs for authenticity. Because
 * re-evaluation REQUIRES the evaluator, this script imports src/ (the allowed
 * direction). That is exactly why it is a separate file from verify.mjs, whose
 * node:-only independence is structural and must never take a src/ import.
 *
 * It shares the very same replayEnvelope() the POST /verify route runs, so the
 * served and offline reproducibility verdicts can never disagree.
 *
 * Usage:
 *   node --experimental-strip-types scripts/replay.ts --evidence <evidence.jws> --pack <pack.json>
 *
 * Exit codes (mirroring verify.mjs discipline):
 *   0 = the decision REPRODUCED (re-evaluation matches the envelope)
 *   1 = NOT REPRODUCED (a verdict: authentic-or-not, the decision does not
 *       re-derive — or the pack/evaluator could not replay it here)
 *   2 = operator/input error (bad usage, unreadable/unparseable input) —
 *       nothing was replayed either way.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { replayEnvelope } from "../src/evidence/replay.ts";
import { loadRulePack } from "../src/rules/loader.ts";

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
    },
  });
  if (!values.evidence || !values.pack) {
    console.error(
      "usage: node --experimental-strip-types scripts/replay.ts --evidence <evidence.jws> --pack <pack.json>",
    );
    process.exit(2);
  }

  // Read + decode. Any file/parse problem is an OPERATOR error (exit 2), never
  // exit 1 — that code is a reproducibility VERDICT, and an unreadable file
  // means nothing was replayed.
  let envelope: Record<string, unknown>;
  let pack;
  try {
    const jws = readFileSync(values.evidence, "utf8").trim();
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
    pack = loadRulePack(readFileSync(values.pack, "utf8"));
  } catch (error) {
    inputError(error instanceof Error ? error.message : String(error));
  }

  console.log("OFFLINE DECISION REPLAY — re-evaluation only, NO signature check");
  console.log(`  evidence: ${values.evidence}`);
  console.log(`  pack:     ${values.pack}`);
  console.log(
    "  NOTE: this tool does NOT verify authenticity — run verifier/verify.mjs",
  );
  console.log(
    "        for the signature/canonical-form/hash checks. Replay only asks:",
  );
  console.log("        does the cited decision re-derive from intent + pack?");
  console.log("");

  // The cited pack must actually BE the pack the envelope references. If the id
  // or version disagree, this is the operator handing the wrong pack — an input
  // error, not a "not reproduced" verdict (mirrors verify.mjs's pack contract).
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

  // id/version do NOT pin pack CONTENT — rule_pack_hash exists precisely because
  // two packs can share an id/version yet differ byte-for-byte. A content-modified
  // pack (same id/version, different hash) would otherwise replay against a pack
  // the envelope never cited and emit a REPRODUCED / NOT-REPRODUCED verdict instead
  // of the operator-error signal. Pin content here too (mirrors the /verify route's
  // `cited.hash === rule_pack_hash` guard, src/routes/verify.ts) so the wrong pack
  // is always exit 2, never a reproducibility verdict against the wrong bytes.
  if (pack.hash !== String(envelope["rule_pack_hash"])) {
    inputError(
      `the --pack provided hashes to ${pack.hash}, but the envelope cites ` +
        `rule_pack_hash ${String(envelope["rule_pack_hash"])} — supply the exact cited pack`,
    );
  }

  const r = replayEnvelope(envelope, pack.pack);
  const citedDecision = String(envelope["decision"]);

  if (!r.replayed) {
    // Pack resolved but the evaluator version is unsupported (D12): replay
    // could not be ATTEMPTED. reproduced is null (unknown), so this is NOT a
    // clean reproduction — exit 1 (a verdict the decision did not replay here).
    console.log("RESULT: NOT REPRODUCED — replay could not be attempted.");
    console.log(`  ${r.detail}`);
    console.log(`  envelope decision: "${citedDecision}"`);
    console.log(`  ${UNCERTIFIED_NOTE}`);
    process.exit(1);
  }

  if (r.reproduced) {
    console.log(
      `RESULT: REPRODUCED — re-evaluation yields decision "${r.decision}" ` +
        `(${JSON.stringify(r.reason_codes)}), matching the envelope.`,
    );
    console.log(`  ${UNCERTIFIED_NOTE}`);
    process.exit(0);
  }

  console.log(
    `RESULT: NOT REPRODUCED — the envelope claims decision "${citedDecision}", ` +
      `but re-evaluation yields "${r.decision}".`,
  );
  if (r.mismatch !== undefined) {
    console.log(`  mismatch: ${r.mismatch}`);
  }
  console.log(
    "  The artifact may be authentic yet record a decision this engine does",
  );
  console.log(
    "  not reproduce (e.g. tampered-then-re-signed). Authenticity is a",
  );
  console.log("  separate question — run verifier/verify.mjs.");
  console.log(`  ${UNCERTIFIED_NOTE}`);
  process.exit(1);
}

main();
