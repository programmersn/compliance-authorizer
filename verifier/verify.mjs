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

// RFC 8785 §3.2.2.2: a "lone surrogate" (an unpaired UTF-16 surrogate) MUST
// cause a compliant JCS implementation to terminate with an error — the RFC's
// rationale is the very interop / broken-signature risk verification guards.
// ES2019 well-formed JSON.stringify ESCAPES it as \udXXX instead of throwing (a
// non-compliant path that strict external verifiers reject), so the rejection
// is an EXPLICIT pre-check. Mirrors src/crypto/canonicalize.ts so the two
// implementations agree on every input, INCLUDING which they reject. Under the
// `u` flag a valid surrogate pair is one non-surrogate code point, so
// \p{Surrogate} matches ONLY an unpaired surrogate. When this throws inside
// verifyEvidence's canonical-form step it is caught into a structured FAIL
// verdict (never a crash) — matching strict verifiers that refuse the escaped
// form.
const LONE_SURROGATE = /\p{Surrogate}/u;

const serializeJcsString = (/** @type {string} */ value) => {
  if (LONE_SURROGATE.test(value)) {
    throw new Error(
      "string contains a lone UTF-16 surrogate (invalid Unicode); RFC 8785 §3.2.2.2 requires termination",
    );
  }
  return JSON.stringify(value);
};

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
  if (type === "boolean") return JSON.stringify(value);
  if (type === "string") return serializeJcsString(value);
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
    out += serializeJcsString(key) + ":" + jcsCanonicalizeAtDepth(member, depth + 1);
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

// ---------------------------------------------------------------------------
// Strict envelope schema (the v0.1 evidence-envelope shape).
//
// The offline verifier is the contract the rendered decision certificate is
// built against, so the envelope-shape check enforces the FULL v0.1 shape — the
// EXACT field set (no unknown fields), plus each field's type and format — not
// merely that the required fields are present. A signed-but-malformed envelope
// is only producible by the key holder (the signature already covers these
// bytes), so this is robustness against a buggy signer, not an outsider-reachable
// hole. The patterns mirror the signing side verbatim (src/evidence/envelope.ts,
// src/rules/pack-schema.ts, src/rules/evaluator.ts); node built-ins only, like
// the rest of this file. The envelope validated here is always the payload this
// verifier itself JSON.parsed (never a caller object), so plain property reads
// are safe — no hostile-getter snapshot is needed.
// ---------------------------------------------------------------------------

// The complete v0.1 field set, in a stable order for the "missing fields"
// message. Reused as the allow-list for the no-unknown-fields check.
const ENVELOPE_FIELDS = [
  "envelope_version", "decision_id", "decision", "reason_codes", "matched_rules",
  "rule_pack_id", "rule_pack_version", "rule_pack_hash", "evaluator_version",
  "intent_hash", "scholar_signature_ref", "payment_intent", "decision_timestamp",
];

const SHA256_HEX = /^[0-9a-f]{64}$/; //                      sha256Hex (src/crypto/hash.ts)
const SEMVER = /^\d+\.\d+\.\d+$/; //                          RulePackSchema.version
const REASON_CODE = /^[A-Z][A-Z0-9_]*$/; //                   RuleSchema.reason_code
const RULE_ID = /^[A-Z0-9][A-Z0-9_-]*$/; //                   RuleSchema.id
const RULE_PACK_ID = /^[a-z0-9][a-z0-9-]*$/; //               RulePackSchema.id
// decision_id is `ev-${randomUUID()}` (src/evidence/envelope.ts). Generic UUID
// shape, NOT v4-pinned — the version/variant nibbles are inside [0-9a-f], so
// pinning them would only risk rejecting a legitimately-generated id.
const DECISION_ID = /^ev-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MATCHED_RULE_DECISIONS = new Set(["deny", "review"]); // RuleSchema.decision

const isNonEmptyString = (/** @type {unknown} */ v) => typeof v === "string" && v.length > 0;
const isPlainObject = (/** @type {unknown} */ v) =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/** @param {Record<string, unknown>} obj @param {string[]} keys exact own-key set */
const hasExactKeys = (obj, keys) => {
  const own = Object.keys(obj);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(obj, key));
};

// A decision_timestamp must be EXACTLY a Date's ISO form — the only thing
// `deps.now().toISOString()` (src/evidence/envelope.ts) ever emits. Round-trip
// equality is the tightest correct check: it accepts that canonical form and
// nothing else (a pattern alone would admit "2026-13-45T99:99:99.999Z").
const isIsoTimestamp = (/** @type {unknown} */ v) => {
  if (typeof v !== "string") return false;
  const date = new Date(v);
  return !Number.isNaN(date.getTime()) && date.toISOString() === v;
};

/** standards_ref: { status:"pending", note: non-empty string }, exact keys. */
function validateStandardsRef(/** @type {unknown} */ value) {
  if (!isPlainObject(value)) return "standards_ref is not an object";
  if (!hasExactKeys(value, ["status", "note"])) return "standards_ref has unexpected or missing fields";
  if (value.status !== "pending") return `standards_ref.status is ${JSON.stringify(value.status)}, expected "pending"`;
  if (!isNonEmptyString(value.note)) return "standards_ref.note is not a non-empty string";
  return null;
}

/** A matched_rules[] entry mirrors MatchedRule (src/rules/evaluator.ts) exactly. */
function validateMatchedRule(/** @type {unknown} */ value, /** @type {number} */ index) {
  const at = `matched_rules[${index}]`;
  if (!isPlainObject(value)) return `${at} is not an object`;
  if (!hasExactKeys(value, ["rule_id", "reason_code", "decision", "title", "description", "standards_ref"]))
    return `${at} has unexpected or missing fields`;
  if (typeof value.rule_id !== "string" || !RULE_ID.test(value.rule_id)) return `${at}.rule_id is malformed`;
  if (typeof value.reason_code !== "string" || !REASON_CODE.test(value.reason_code)) return `${at}.reason_code is malformed`;
  if (!MATCHED_RULE_DECISIONS.has(value.decision)) return `${at}.decision is not "deny" or "review"`;
  if (!isNonEmptyString(value.title)) return `${at}.title is not a non-empty string`;
  if (!isNonEmptyString(value.description)) return `${at}.description is not a non-empty string`;
  const refError = validateStandardsRef(value.standards_ref);
  return refError ? `${at}.${refError}` : null;
}

/** scholar_signature_ref: the UNCERTIFIED specimen (src/evidence/envelope.ts). */
function validateScholarSignatureRef(/** @type {unknown} */ value) {
  if (!isPlainObject(value)) return "scholar_signature_ref is not an object";
  if (!hasExactKeys(value, ["status", "statement", "scholar_did", "signature", "certification_note"]))
    return "scholar_signature_ref has unexpected or missing fields";
  if (value.status !== "uncertified") return `scholar_signature_ref.status is ${JSON.stringify(value.status)}, expected "uncertified"`;
  if (!isNonEmptyString(value.statement)) return "scholar_signature_ref.statement is not a non-empty string";
  if (value.scholar_did !== null) return "scholar_signature_ref.scholar_did must be null on an UNCERTIFIED envelope";
  if (value.signature !== null) return "scholar_signature_ref.signature must be null on an UNCERTIFIED envelope";
  if (!isNonEmptyString(value.certification_note)) return "scholar_signature_ref.certification_note is not a non-empty string";
  return null;
}

/**
 * Strict structural validation of the v0.1 envelope, run AFTER the
 * required-field-presence and decision-enum checks (so this only ever sees an
 * object that already has every required field and a valid decision). Returns a
 * precise failure reason naming the offending field, or null when the envelope
 * conforms exactly. Shape only — cross-field consistency (intent_hash,
 * rule_pack_hash, the replayed decision) is the job of the later checks.
 *
 * @param {Record<string, unknown>} envelope
 * @returns {string | null}
 */
function validateEnvelopeStrict(envelope) {
  // No unknown fields: the field set is exactly the v0.1 schema. Pairs with the
  // exact-version pin below — together they bind this verifier to v0.1, so a
  // future envelope_version is reported plainly instead of as an unknown-field
  // cascade.
  const unknown = Object.keys(envelope).filter((key) => !ENVELOPE_FIELDS.includes(key));
  if (unknown.length > 0) return `unknown field(s): ${unknown.sort().join(", ")}`;

  if (envelope.envelope_version !== "0.1.0")
    return `envelope_version is ${JSON.stringify(envelope.envelope_version)} — this verifier handles "0.1.0"`;
  if (typeof envelope.decision_id !== "string" || !DECISION_ID.test(envelope.decision_id))
    return "decision_id is not an ev-<uuid> identifier";
  if (!isIsoTimestamp(envelope.decision_timestamp))
    return "decision_timestamp is not an ISO-8601 instant (Date.toISOString form)";
  if (typeof envelope.evaluator_version !== "string" || !SEMVER.test(envelope.evaluator_version))
    return "evaluator_version is not a semver string";
  if (typeof envelope.rule_pack_id !== "string" || !RULE_PACK_ID.test(envelope.rule_pack_id))
    return "rule_pack_id is malformed";
  if (typeof envelope.rule_pack_version !== "string" || !SEMVER.test(envelope.rule_pack_version))
    return "rule_pack_version is not a semver string";
  if (typeof envelope.rule_pack_hash !== "string" || !SHA256_HEX.test(envelope.rule_pack_hash))
    return "rule_pack_hash is not a lowercase sha256 hex digest";
  if (typeof envelope.intent_hash !== "string" || !SHA256_HEX.test(envelope.intent_hash))
    return "intent_hash is not a lowercase sha256 hex digest";

  // reason_codes: array of reason-code strings (empty is valid — e.g. an allow
  // that matched no rule). Shape only; that it equals the matched_rules' codes
  // is re-derived by replay, not asserted here.
  if (!Array.isArray(envelope.reason_codes)) return "reason_codes is not an array";
  for (let i = 0; i < envelope.reason_codes.length; i++) {
    const code = envelope.reason_codes[i];
    if (typeof code !== "string" || !REASON_CODE.test(code))
      return `reason_codes[${i}] is not a valid reason code`;
  }

  // matched_rules: array of MatchedRule (empty is valid — an allow/default).
  if (!Array.isArray(envelope.matched_rules)) return "matched_rules is not an array";
  for (let i = 0; i < envelope.matched_rules.length; i++) {
    const ruleError = validateMatchedRule(envelope.matched_rules[i], i);
    if (ruleError) return ruleError;
  }

  const scholarError = validateScholarSignatureRef(envelope.scholar_signature_ref);
  if (scholarError) return scholarError;

  // payment_intent is an opaque object (its hash is bound by intent_hash; its
  // internal shape is the rule pack's concern, not the envelope schema's).
  if (!isPlainObject(envelope.payment_intent)) return "payment_intent is not a JSON object";

  return null;
}

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

  // 6. Envelope shape — the EXACT v0.1 schema, not just required-field presence.
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return fail("envelope-shape", "Evidence envelope shape", "payload is not a JSON object");
  }
  const missing = ENVELOPE_FIELDS.filter((field) => !(field in envelope));
  if (missing.length > 0) {
    return fail("envelope-shape", "Evidence envelope shape", `missing fields: ${missing.join(", ")}`);
  }
  if (!DECISIONS.has(envelope.decision)) {
    return fail("envelope-shape", "Evidence envelope shape",
      `decision ${JSON.stringify(envelope.decision)} is not one of allow/review/deny`);
  }
  // Strict pass: exact field set (no unknown fields) + every field's type/format.
  const schemaError = validateEnvelopeStrict(envelope);
  if (schemaError !== null) {
    return fail("envelope-shape", "Evidence envelope shape", schemaError);
  }
  pass("envelope-shape", "Evidence envelope shape",
    `decision "${envelope.decision}", v0.1 schema valid (exact field set, types, formats)`);

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
