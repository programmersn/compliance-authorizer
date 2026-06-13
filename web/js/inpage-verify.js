/**
 * In-page (courtesy) verification of an evidence artifact with WebCrypto.
 *
 * HONESTY FRAMING: these checks consult the SAME server that issued the
 * envelope (its JWKS, its rule-pack route), so they prove integrity and
 * self-consistency — not independence. The standalone offline verifier
 * (verifier/verify.mjs) remains the truly-independent path; the certificate
 * says so next to these statuses.
 *
 * The checks mirror the hard verifiers where it matters:
 *   - alg is pinned to exactly "EdDSA" BEFORE any key material is touched
 *     (alg:none and substituted algorithms are rejected);
 *   - the JWKS key is resolved by the protected-header kid, read once;
 *   - kid must equal the key's own RFC 7638 thumbprint (no swapped material);
 *   - Ed25519 signatures must be exactly 64 bytes.
 */

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Decode unpadded base64url. Throws on anything else — padding or foreign
 * characters never silently decode.
 * @param {string} text
 * @returns {Uint8Array}
 */
export function b64urlToBytes(text) {
  if (typeof text !== "string" || text === "" || !B64URL_RE.test(text)) {
    throw new Error("not unpadded base64url");
  }
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  // Reject NON-CANONICAL base64url (a final character's unused don't-care bits):
  // atob maps several texts to the same bytes (e.g. "AA" and "AB" both decode to
  // 0x00). The offline verifier (verifier/verify.mjs) and src/vc/verify.ts reject
  // these as malleable via a decode -> re-encode round-trip; the in-page path MUST
  // reach the SAME verdict or the independent-verifier claim breaks. bytesToB64url
  // emits canonical, unpadded base64url, so the round-trip pins the encoding.
  if (bytesToB64url(bytes) !== text) {
    throw new Error("not canonical unpadded base64url (malleable encoding rejected)");
  }
  return bytes;
}

/** @param {Uint8Array} bytes @returns {string} unpadded base64url */
export function bytesToB64url(bytes) {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Parse a JWS-compact string and pin the protected header. Throws on any
 * structural defect, on alg !== "EdDSA" (checked BEFORE keys), on crit, on a
 * missing kid.
 * @param {string} jws
 * @returns {{headerB64:string, payloadB64:string, signatureB64:string, header:{alg:string, kid:string}}}
 */
export function parseCompactJws(jws) {
  if (typeof jws !== "string") throw new Error("JWS must be a string");
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("JWS-compact must have exactly 3 segments");
  const [headerB64, payloadB64, signatureB64] = parts;
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(headerB64)));
  } catch {
    throw new Error("protected header is not valid base64url JSON");
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("protected header is not a JSON object");
  }
  // Pin the algorithm BEFORE any key material is touched (negative-alg guard).
  if (header.alg !== "EdDSA") {
    throw new Error(`alg must be exactly "EdDSA" (got ${JSON.stringify(header.alg)})`);
  }
  if ("crit" in header) throw new Error("crit header parameters are not supported");
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new Error("protected header must carry a non-empty kid");
  }
  return { headerB64, payloadB64, signatureB64, header: { alg: "EdDSA", kid: header.kid } };
}

/** Decode the envelope JSON out of a JWS-compact artifact (display only). */
export function decodeEnvelope(jws) {
  const parsed = parseCompactJws(jws);
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(parsed.payloadB64)));
}

/** @param {string} text @returns {Promise<string>} lowercase-hex SHA-256 */
export async function sha256HexOfText(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * RFC 7638 JWK thumbprint for an Ed25519 OKP public key: the base64url SHA-256
 * of the canonical {"crv","kty","x"} JSON. `x` is itself base64url, so no JSON
 * escaping can occur in this fixed template.
 * @param {string} x
 * @returns {Promise<string>}
 */
export async function computeOkpThumbprint(x) {
  if (typeof x !== "string" || !B64URL_RE.test(x)) throw new Error("x must be base64url");
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return bytesToB64url(new Uint8Array(digest));
}

/**
 * Verify the Ed25519 signature of a JWS-compact evidence artifact against a
 * JWKS. Never throws — returns a verdict object so the UI can render an honest
 * status either way.
 * @param {string} jws
 * @param {{keys?: unknown[]}} jwks
 * @returns {Promise<{ok:boolean, kid?:string, reason?:string, unsupported?:boolean}>}
 */
export async function verifyEnvelopeSignature(jws, jwks) {
  let parsed;
  try {
    parsed = parseCompactJws(jws);
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }

  const keys = jwks !== null && typeof jwks === "object" && Array.isArray(jwks.keys) ? jwks.keys : [];
  const found = keys.find(
    (key) => key !== null && typeof key === "object" && /** @type {any} */ (key).kid === parsed.header.kid,
  );
  if (!found) return { ok: false, reason: `kid ${parsed.header.kid} not present in the JWKS` };

  // Single read per field; the kid is bound to the PROTECTED-HEADER kid.
  const jwk = {
    kty: /** @type {any} */ (found).kty,
    crv: /** @type {any} */ (found).crv,
    x: /** @type {any} */ (found).x,
    kid: parsed.header.kid,
  };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    return { ok: false, reason: "JWKS key is not an Ed25519 OKP key" };
  }

  if (typeof crypto === "undefined" || !crypto.subtle) {
    return { ok: false, unsupported: true, reason: "WebCrypto is unavailable in this browser" };
  }

  // kid integrity: kid MUST be the key's own RFC 7638 thumbprint (parity with
  // verifier/verify.mjs and src/crypto/jws.ts — no swapped key material).
  let thumbprint;
  try {
    thumbprint = await computeOkpThumbprint(jwk.x);
  } catch {
    return { ok: false, reason: "JWKS key material is not valid base64url" };
  }
  if (thumbprint !== jwk.kid) {
    return { ok: false, reason: "JWKS kid is not the key's RFC 7638 thumbprint — key material may have been swapped" };
  }

  let signature;
  try {
    signature = b64urlToBytes(parsed.signatureB64);
  } catch {
    return { ok: false, reason: "signature segment is not unpadded base64url" };
  }
  if (signature.length !== 64) {
    return { ok: false, reason: "Ed25519 signature is not exactly 64 bytes" };
  }

  let key;
  try {
    key = await crypto.subtle.importKey("raw", b64urlToBytes(jwk.x), { name: "Ed25519" }, false, [
      "verify",
    ]);
  } catch {
    return {
      ok: false,
      unsupported: true,
      reason: "Ed25519 is not supported by this browser's WebCrypto — run the offline verifier",
    };
  }

  const data = new TextEncoder().encode(`${parsed.headerB64}.${parsed.payloadB64}`);
  let verified;
  try {
    verified = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
  } catch {
    return { ok: false, reason: "signature verification errored in this browser" };
  }
  return verified
    ? { ok: true, kid: parsed.header.kid }
    : { ok: false, reason: "Ed25519 signature verification failed" };
}
