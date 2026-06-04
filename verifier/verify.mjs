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
 * Exit code 0 = every check passed. Exit code 1 = at least one check failed.
 */
import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) — independent re-implementation. Kept separate from
// src/crypto/canonicalize.ts ON PURPOSE.
// ---------------------------------------------------------------------------

/** @param {unknown} value @returns {string} */
export function jcsCanonicalize(value) {
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
      out += jcsCanonicalize(value[i]);
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
    out += JSON.stringify(key) + ":" + jcsCanonicalize(member);
  }
  return out + "}";
}

const sha256Hex = (/** @type {string|Buffer} */ data) =>
  createHash("sha256").update(data).digest("hex");

const b64urlDecode = (/** @type {string} */ text) => Buffer.from(text, "base64url");

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

  // 1. Structure
  const parts = typeof jws === "string" ? jws.trim().split(".") : [];
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    return fail("structure", "JWS-compact structure", "expected 3 non-empty dot-separated segments");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  let header;
  try {
    header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  } catch {
    return fail("structure", "JWS-compact structure", "protected header is not valid JSON");
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
  const jwk = keys.find((key) => key && typeof key === "object" && key.kid === header.kid);
  if (!jwk) {
    return fail("key-resolution", "Issuer key resolution", `kid ${header.kid} not found in the provided JWKS`);
  }
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
  issuer = { kid: jwk.kid, did: didKeyFromJwkX(jwk.x) };
  pass("key-resolution", "Issuer key resolution", `kid resolves to an Ed25519 key; RFC 7638 thumbprint matches`);

  // 4. Signature
  let publicKey;
  try {
    publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  } catch {
    return fail("signature", "Ed25519 signature", "public key could not be imported");
  }
  const signatureValid = ed25519Verify(
    null,
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    publicKey,
    b64urlDecode(signatureB64),
  );
  if (!signatureValid) {
    return fail("signature", "Ed25519 signature", "signature does NOT verify — the evidence has been tampered with or was not issued by this key");
  }
  pass("signature", "Ed25519 signature", "signature verifies over the protected header + payload");

  // 5. Canonical form — the payload must BE its own RFC 8785 form.
  const payloadBytes = b64urlDecode(payloadB64);
  let envelope;
  try {
    envelope = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return fail("canonical-form", "Payload is canonical JSON (RFC 8785)", "payload is not valid JSON");
  }
  if (Buffer.from(jcsCanonicalize(envelope), "utf8").compare(payloadBytes) !== 0) {
    return fail("canonical-form", "Payload is canonical JSON (RFC 8785)",
      "payload bytes differ from the canonical serialization of their own content");
  }
  pass("canonical-form", "Payload is canonical JSON (RFC 8785)", "payload bytes equal their canonical re-serialization");

  // 6. Envelope shape
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

  const jws = readFileSync(values.evidence, "utf8");
  const jwks = JSON.parse(readFileSync(values.jwks, "utf8"));
  const pack = values.pack ? JSON.parse(readFileSync(values.pack, "utf8")) : undefined;

  console.log("OFFLINE EVIDENCE VERIFICATION — zero server trust, node built-ins only");
  console.log(`  evidence: ${values.evidence}`);
  console.log(`  jwks:     ${values.jwks}`);
  console.log(`  pack:     ${values.pack ?? "(not provided — rule_pack_hash not checked)"}`);
  console.log("");

  const result = verifyEvidence({ jws, jwks, pack });
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
