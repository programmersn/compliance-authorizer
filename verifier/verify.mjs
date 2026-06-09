#!/usr/bin/env node
/**
 * Standalone OFFLINE evidence verifier — the zero-server-trust path (CXT-A).
 *
 * Design constraints (deliberate, do not "fix"):
 *   - Node BUILT-INS ONLY. No npm dependencies, no imports from the service
 *     source (src/). This file re-implements base64url handling, RFC 8785
 *     canonicalization, and JWS verification from scratch, so a verification
 *     here never inherits a signing-side bug. Property-based tests assert the
 *     two canonicalizers agree (test/crypto/properties.test.ts).
 *   - ZERO network access. Everything is read from local files.
 *   - The ONLY accepted signature algorithm is "EdDSA" (Ed25519). alg:none,
 *     HS256-substitution, or any other alg is rejected before key material is
 *     ever touched.
 *
 * Usage:
 *   node verifier/verify.mjs --evidence <evidence.jws> --jwks <jwks.json> [--pack <pack.json>]
 *
 * Exit codes: 0 = every check passed; 1 = at least one check failed (the
 * artifact is NOT valid evidence); 2 = operator/input error (bad usage or
 * unreadable/unparseable input files — nothing was verified either way).
 */
import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) — independent re-implementation. Kept separate from
// src/crypto/canonicalize.ts ON PURPOSE.
// ---------------------------------------------------------------------------

// Nesting bound: RFC 8785 imposes none, but unbounded recursion over hostile
// input is a stack-overflow crash. Pinned to the SAME value as the signing
// side (src/crypto/canonicalize.ts) so the two implementations keep agreeing.
const MAX_CANONICALIZATION_DEPTH = 200;

/** @param {unknown} value @returns {string} */
export function jcsCanonicalize(value) {
  return jcsCanonicalizeAtDepth(value, 0);
}

/** @param {unknown} value @param {number} depth @returns {string} */
function jcsCanonicalizeAtDepth(value, depth) {
  if (depth > MAX_CANONICALIZATION_DEPTH) {
    throw new Error(
      `nesting exceeds the canonicalization depth bound (${MAX_CANONICALIZATION_DEPTH})`,
    );
  }
  if (value === null) return "null";
  const type = typeof value;
  if (type === "boolean" || type === "string") return JSON.stringify(value);
  if (type === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in JCS input");
    return JSON.stringify(value);
  }
  if (type !== "object") throw new Error(`non-JSON type "${type}" in JCS input`);
  if (Array.isArray(value)) {
    let out = "[";
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out += ",";
      out += jcsCanonicalizeAtDepth(value[i], depth + 1);
    }
    return out + "]";
  }
  const keys = Object.keys(value).sort(); // UTF-16 code unit order (RFC 8785 §3.2.3)
  let out = "{";
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const member = /** @type {Record<string, unknown>} */ (value)[key];
    if (member === undefined) throw new Error(`undefined member "${key}" in JCS input`);
    if (i > 0) out += ",";
    out += JSON.stringify(key) + ":" + jcsCanonicalizeAtDepth(member, depth + 1);
  }
  return out + "}";
}

const sha256Hex = (/** @type {string|Buffer} */ data) =>
  createHash("sha256").update(data).digest("hex");

const b64urlDecode = (/** @type {string} */ text) => Buffer.from(text, "base64url");

// RFC 7515 base64url segments are canonical and UNPADDED. Node's base64url
// decoder is lenient: it ignores `=` padding and the low "don't-care" bits of a
// segment's final character, so MANY distinct strings decode to the same bytes.
// For the signature segment — the one segment the signature itself cannot cover —
// that is malleability: from ANY valid artifact an attacker can mint byte-different
// ones that all still verify. Reject every non-canonical encoding by requiring each
// segment to round-trip exactly: decode, then re-encode, must reproduce the input.
// (The payload is independently pinned by the canonical-form check and the header
// by the signature; this brings the signature segment up to the same standard.)
const isCanonicalB64url = (/** @type {string} */ text) =>
  Buffer.from(text, "base64url").toString("base64url") === text;

// did:key encoding of the VERIFYING key (multicodec ed25519-pub 0xed01,
// multibase base58btc) — printed so the operator can compare the fingerprint
// against the issuer's out-of-band published did:key. A signature verifier can
// only prove consistency with the JWKS it is handed; WHICH issuer that JWKS
// belongs to is established by this fingerprint comparison.
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** @param {Buffer} bytes @returns {string} */
function base58btcEncode(bytes) {
  let n = 0n;
  for (const byte of bytes) n = n * 256n + BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = BASE58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = "1" + out;
  }
  return out;
}

/** @param {string} x base64url raw Ed25519 public key @returns {string} */
function didKeyFromJwkX(x) {
  const raw = b64urlDecode(x);
  return `did:key:z${base58btcEncode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]))}`;
}

// ---------------------------------------------------------------------------
// Verification checks. Each returns {id, title, ok, detail}.
// ---------------------------------------------------------------------------

const DECISIONS = new Set(["allow", "review", "deny"]);

/**
 * Verify a JWS-compact evidence artifact against a JWKS (and optionally the
 * rule pack it cites). Pure function over the provided documents — no I/O.
 *
 * @param {{ jws: string, jwks: { keys?: unknown[] }, pack?: unknown }} input
 * @returns {{ ok: boolean, checks: Array<{id: string, title: string, ok: boolean, detail: string}>, envelope: Record<string, unknown> | null, issuer: { kid: string, did: string } | null }}
 */
export function verifyEvidence({ jws, jwks, pack }) {
  /** @type {Array<{id: string, title: string, ok: boolean, detail: string}>} */
  const checks = [];
  /** @type {{ kid: string, did: string } | null} */
  let issuer = null;
  const fail = (id, title, detail) => {
    checks.push({ id, title, ok: false, detail });
    return { ok: false, checks, envelope: null, issuer };
  };
  const pass = (id, title, detail) => checks.push({ id, title, ok: true, detail });

  // 1. Structure. The artifact is the EXACT compact JWS. Surrounding whitespace is
  // file framing, NOT part of the evidence, and is not stripped here — so `artifact`
  // and `artifact + "\n"` are never treated as the same JWS. This keeps the verifier
  // in lockstep with verifyCompact (src/crypto/jws.ts), which also never trims; the
  // CLI tolerates a file's trailing newline by trimming at the I/O boundary instead.
  const parts = typeof jws === "string" ? jws.split(".") : [];
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return fail("structure", "JWS-compact structure", "expected 3 non-empty dot-separated segments");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  // Reject non-canonical base64url BEFORE any key material is touched: padding, a
  // non-canonical final character, or stray characters (surrounding whitespace lands
  // INSIDE a segment) are all rejected here, so an artifact cannot be malleated into
  // a byte-different string that still verifies.
  if (!parts.every(isCanonicalB64url)) {
    return fail("structure", "JWS-compact structure",
      "a segment is not canonical unpadded base64url (RFC 7515) — non-canonical encodings are rejected as malleable");
  }
  let header;
  try {
    header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  } catch {
    return fail("structure", "JWS-compact structure", "protected header is not valid JSON");
  }
  // JSON.parse can yield null/arrays/primitives — only an OBJECT is a header.
  // (Without this guard, `null` would crash property access with a TypeError
  // instead of producing a structured FAIL verdict.)
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    return fail("structure", "JWS-compact structure", "protected header is not a JSON object");
  }
  pass("structure", "JWS-compact structure", "3 segments, protected header parses");

  // 2. Algorithm pinning — BEFORE any key material is touched.
  if (header.alg !== "EdDSA") {
    return fail("alg-pinned", "Signature algorithm pinned to EdDSA",
      `alg is ${JSON.stringify(header.alg)} — only "EdDSA" evidence is accepted (alg:none and substituted algorithms are rejected)`);
  }
  if ("crit" in header) {
    return fail("alg-pinned", "Signature algorithm pinned to EdDSA", "crit header parameters are not supported");
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    return fail("alg-pinned", "Signature algorithm pinned to EdDSA", "protected header carries no kid");
  }
  pass("alg-pinned", "Signature algorithm pinned to EdDSA", 'alg is exactly "EdDSA", no crit params');

  // 3. Key resolution + kid integrity (kid must BE the RFC 7638 thumbprint).
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  const found = keys.find((key) => key && typeof key === "object" && key.kid === header.kid);
  if (!found) {
    return fail("key-resolution", "Issuer key resolution", `kid ${header.kid} not found in the provided JWKS`);
  }
  // Snapshot the matched key with a SINGLE read per field. verifyEvidence is
  // EXPORTED and accepts arbitrary objects, so reading `found.x` once for the
  // thumbprint and again to build the verifying key would let a hostile getter/
  // Proxy present an honest x to the kid==thumbprint check and an attacker x to
  // the signature (a property-read TOCTOU → key substitution under a trusted
  // kid). Use ONLY this snapshot below — never the caller's object. The kid is
  // bound to the PROTECTED-HEADER kid (already matched at find), NOT a second read
  // of found.kid: a hostile kid getter could otherwise return the header kid at
  // find and an attacker kid here, and the thumbprint check would bind x to the
  // attacker kid — verifying under a key whose kid disagrees with the artifact's.
  // Mirrors verifyCompact's per-key snapshot in src/crypto/jws.ts.
  const jwk = { kty: found.kty, crv: found.crv, x: found.x, kid: header.kid };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    return fail("key-resolution", "Issuer key resolution", "JWKS key is not an Ed25519 OKP key");
  }
  const thumbprint = createHash("sha256")
    .update(`{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(jwk.x)}}`)
    .digest("base64url");
  if (thumbprint !== jwk.kid) {
    return fail("key-resolution", "Issuer key resolution",
      "JWKS kid does not match the key's RFC 7638 thumbprint — key material may have been swapped");
  }
  pass("key-resolution", "Issuer key resolution", `kid resolves to an Ed25519 key; RFC 7638 thumbprint matches`);

  // 4. Signature
  let publicKey;
  try {
    publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  } catch {
    return fail("signature", "Ed25519 signature", "public key could not be imported");
  }
  const signatureBytes = b64urlDecode(signatureB64);
  if (signatureBytes.length !== 64) {
    return fail("signature", "Ed25519 signature",
      "signature segment does not decode to exactly 64 bytes (Ed25519)");
  }
  const signatureValid = ed25519Verify(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    publicKey,
    signatureBytes,
  );
  if (!signatureValid) {
    return fail("signature", "Ed25519 signature", "signature does NOT verify — the evidence has been tampered with or was not issued by this key");
  }
  // Populate `issuer` ONLY now that the signature has verified — never at key
  // resolution above. `issuer` names the key that ACTUALLY signed these bytes, so
  // a signature failure must leave it null (the exported API never surfaces a
  // claimed-but-unverified identity). A LATER non-signature check may still fail
  // (e.g. a non-envelope payload); the signer is genuine there, so issuer stays
  // set — that is the independent-encoder fingerprint the tests assert.
  issuer = { kid: jwk.kid, did: didKeyFromJwkX(jwk.x) };
  pass("signature", "Ed25519 signature", "signature verifies over the protected header + payload");

  // 5. Canonical form — the payload must BE its own RFC 8785 form.
  const payloadBytes = b64urlDecode(payloadB64);
  let envelope;
  try {
    envelope = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return fail("canonical-form", "Payload is canonical JSON (RFC 8785)", "payload is not valid JSON");
  }
  let canonicalEnvelope;
  try {
    canonicalEnvelope = jcsCanonicalize(envelope);
  } catch (error) {
    // e.g. nesting beyond the depth bound — the payload's canonical form
    // cannot be confirmed, so this is a structured FAIL, never a crash.
    return fail("canonical-form", "Payload is canonical JSON (RFC 8785)",
      `payload cannot be canonicalized: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (Buffer.from(canonicalEnvelope, "utf8").compare(payloadBytes) !== 0) {
    return fail("canonical-form", "Payload is canonical JSON (RFC 8785)",
      "payload bytes differ from the canonical serialization of their own content");
  }
  pass("canonical-form", "Payload is canonical JSON (RFC 8785)", "payload bytes equal their canonical re-serialization");

  // 6. Envelope shape
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return fail("envelope-shape", "Evidence envelope shape", "payload is not a JSON object");
  }
  const required = [
    "envelope_version", "decision_id", "decision", "reason_codes", "matched_rules",
    "rule_pack_id", "rule_pack_version", "rule_pack_hash", "evaluator_version",
    "intent_hash", "scholar_signature_ref", "payment_intent", "decision_timestamp",
  ];
  const missing = required.filter((field) => !(field in envelope));
  if (missing.length > 0) {
    return fail("envelope-shape", "Evidence envelope shape", `missing fields: ${missing.join(", ")}`);
  }
  if (!DECISIONS.has(envelope.decision)) {
    return fail("envelope-shape", "Evidence envelope shape",
      `decision ${JSON.stringify(envelope.decision)} is not one of allow/review/deny`);
  }
  pass("envelope-shape", "Evidence envelope shape", `decision "${envelope.decision}", all required fields present`);

  // 7. Intent hash
  const intentHash = sha256Hex(jcsCanonicalize(envelope.payment_intent));
  if (intentHash !== envelope.intent_hash) {
    return fail("intent-hash", "intent_hash recomputation",
      "sha256(JCS(payment_intent)) does not match the envelope's intent_hash");
  }
  pass("intent-hash", "intent_hash recomputation", "sha256(JCS(payment_intent)) matches");

  // 8. Rule-pack hash (only when the pack is provided)
  if (pack !== undefined) {
    const packHash = sha256Hex(jcsCanonicalize(pack));
    if (packHash !== envelope.rule_pack_hash) {
      return fail("pack-hash", "rule_pack_hash recomputation",
        "sha256(JCS(rule pack)) does not match the envelope's rule_pack_hash — wrong or modified pack");
    }
    const packObj = /** @type {Record<string, unknown>} */ (pack);
    if (packObj.id !== envelope.rule_pack_id || packObj.version !== envelope.rule_pack_version) {
      return fail("pack-hash", "rule_pack_hash recomputation",
        "pack id/version do not match the envelope's rule_pack_id/rule_pack_version");
    }
    if (packObj.required_evaluator_version !== envelope.evaluator_version) {
      return fail("pack-hash", "rule_pack_hash recomputation",
        "pack required_evaluator_version does not match the envelope's evaluator_version (D12 seam)");
    }
    pass("pack-hash", "rule_pack_hash recomputation", "sha256(JCS(pack)) matches; id/version/evaluator_version consistent");
  }

  return { ok: true, checks, envelope, issuer };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function main() {
  const { values } = parseArgs({
    options: {
      evidence: { type: "string" },
      jwks: { type: "string" },
      pack: { type: "string" },
    },
  });
  if (!values.evidence || !values.jwks) {
    console.error("usage: node verifier/verify.mjs --evidence <evidence.jws> --jwks <jwks.json> [--pack <pack.json>]");
    process.exit(2);
  }

  // Input problems are OPERATOR errors (exit 2, like bad usage) — never exit 1,
  // which is reserved for "this artifact is NOT valid evidence". An unreadable
  // file means nothing was verified, and the exit code must not say otherwise.
  let jws, jwks, pack;
  try {
    // Trim file framing (e.g. a trailing newline) at the I/O boundary — it is not
    // part of the evidence artifact. The verifier itself treats its input as exact.
    jws = readFileSync(values.evidence, "utf8").trim();
    jwks = JSON.parse(readFileSync(values.jwks, "utf8"));
    pack = values.pack ? JSON.parse(readFileSync(values.pack, "utf8")) : undefined;
  } catch (error) {
    console.error(`INPUT ERROR (nothing was verified): ${error instanceof Error ? error.message : String(error)}`);
    console.error("Could not read or parse the provided files — operator/input problem, NOT a verification verdict.");
    process.exit(2);
  }

  console.log("OFFLINE EVIDENCE VERIFICATION — zero server trust, node built-ins only");
  console.log(`  evidence: ${values.evidence}`);
  console.log(`  jwks:     ${values.jwks}`);
  console.log(`  pack:     ${values.pack ?? "(not provided — rule_pack_hash not checked)"}`);
  console.log("");

  // Catch-all: a verifier malfunction must NEVER exit 1 — that code is a
  // verification VERDICT ("not valid evidence"), and a crash is not a verdict.
  let result;
  try {
    result = verifyEvidence({ jws, jwks, pack });
  } catch (error) {
    console.error(`VERIFIER ERROR (nothing was verified): ${error instanceof Error ? error.message : String(error)}`);
    console.error("The verifier failed before reaching a verdict — operator/input problem, NOT a verification verdict.");
    process.exit(2);
  }
  for (const check of result.checks) {
    console.log(`  [${check.ok ? "PASS" : "FAIL"}] ${check.title}`);
    console.log(`         ${check.detail}`);
  }
  console.log("");

  if (result.ok && result.envelope) {
    const env = result.envelope;
    console.log(`RESULT: PASS — decision "${env.decision}" (${JSON.stringify(env.reason_codes)})`);
    console.log(`  rule pack:  ${env.rule_pack_id}@${env.rule_pack_version} (${env.rule_pack_hash})`);
    console.log(`  evaluator:  ${env.evaluator_version}   intent_hash: ${env.intent_hash}`);
    if (result.issuer) {
      console.log(`  signed by:  kid ${result.issuer.kid}`);
      console.log(`              ${result.issuer.did}`);
      console.log(`  TRUST ANCHOR: a verifier proves consistency with the JWKS you hand it.`);
      console.log(`  Confirm this did:key fingerprint against the issuer's published key`);
      console.log(`  (obtained out-of-band) before treating the evidence as theirs.`);
      console.log(`  SCOPE: PASS proves authenticity and integrity (signature, canonical`);
      console.log(`  form, hashes). It does NOT re-run the rule evaluator — replaying the`);
      console.log(`  decision additionally requires the matching evaluator (evaluator_version above).`);
    }
    console.log(`  NOTE: UNCERTIFIED — synthetic demo rule pack; not a fatwa / not certified / not production advice.`);
    process.exit(0);
  }
  console.log("RESULT: FAIL — this artifact is NOT valid evidence.");
  process.exit(1);
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) main();
