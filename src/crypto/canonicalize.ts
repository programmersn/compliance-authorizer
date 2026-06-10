/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS).
 *
 * This is the SIGNING-side implementation. The standalone offline verifier
 * (verifier/verify.mjs) deliberately re-implements JCS with zero shared code so
 * that verification never inherits a signing-side bug; property-based tests
 * assert the two implementations agree on arbitrary JSON values
 * (test/crypto/properties.test.ts).
 *
 * Strictness: hash inputs must never be guessed. Anything that is not plain
 * JSON data — undefined, functions, symbols, bigints, non-finite numbers,
 * class instances (Date, Map, ...) — throws instead of being silently coerced.
 */

export class CanonicalizationError extends Error {
  override name = "CanonicalizationError";
}

/**
 * Nesting bound for canonicalization. RFC 8785 imposes none, but unbounded
 * recursion over hostile input is a stack-overflow crash; legitimate envelopes
 * are ~4 levels deep. The standalone verifier pins the SAME bound so the two
 * implementations keep agreeing on every input (property-tested).
 */
export const MAX_CANONICALIZATION_DEPTH = 200;

/**
 * RFC 8785 §3.2.2.2: invalid Unicode such as a "lone surrogate" (an unpaired
 * UTF-16 surrogate code unit, e.g. U+D800 with no following low surrogate)
 * "MUST cause a compliant JCS implementation to terminate with an appropriate
 * error" — the RFC's own rationale is the exact interop / broken-signature risk
 * this canonicalizer exists to prevent. ES2019 "well-formed JSON.stringify"
 * ESCAPES a lone surrogate as \udXXX rather than throwing, which is a
 * NON-compliant code path: strict external JCS verifiers (the RFC author's Go
 * reference, gowebpki/jcs, json-canon) REJECT that form, so an artifact carrying
 * one would fail to verify elsewhere. Because JSON.stringify silently escapes
 * (it never throws here), the rejection MUST be an explicit pre-check.
 *
 * Under the `u` flag a string is matched per code POINT, so a valid high+low
 * surrogate pair is a single non-surrogate code point; the ONLY way
 * \p{Surrogate} can match is an UNPAIRED (lone) surrogate. Mirrored verbatim in
 * the standalone verifier's jcsCanonicalize (verifier/verify.mjs) so the two
 * implementations agree on every input — INCLUDING which inputs they reject
 * (property-tested, test/crypto/properties.test.ts).
 */
const LONE_SURROGATE = /\p{Surrogate}/u;

function serializeString(value: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new CanonicalizationError(
      "string contains a lone UTF-16 surrogate (invalid Unicode); RFC 8785 §3.2.2.2 requires termination",
    );
  }
  return JSON.stringify(value);
}

/**
 * Serialize a JSON-compatible value to its RFC 8785 canonical form.
 *
 * - Object members are sorted by UTF-16 code units of their names (§3.2.3),
 *   which is exactly ECMAScript's default string sort order.
 * - Strings and finite numbers are serialized via JSON.stringify, which RFC 8785
 *   defines as the normative serialization (§3.2.2.1, §3.2.2.3) — including
 *   -0 → "0" and shortest-round-trip number formatting.
 */
export function canonicalize(value: unknown): string {
  return canonicalizeAtDepth(value, 0);
}

function canonicalizeAtDepth(value: unknown, depth: number): string {
  if (depth > MAX_CANONICALIZATION_DEPTH) {
    throw new CanonicalizationError(
      `nesting exceeds the canonicalization depth bound (${MAX_CANONICALIZATION_DEPTH})`,
    );
  }
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(
          `non-finite number cannot be canonicalized: ${String(value)}`,
        );
      }
      return JSON.stringify(value);
    case "string":
      return serializeString(value);
    case "object":
      break; // handled below
    default:
      throw new CanonicalizationError(
        `value of type "${typeof value}" cannot be canonicalized`,
      );
  }

  if (Array.isArray(value)) {
    return `[${value.map((element) => canonicalizeAtDepth(element, depth + 1)).join(",")}]`;
  }

  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CanonicalizationError(
      "only plain objects can be canonicalized (no class instances)",
    );
  }

  const record = value as Record<string, unknown>;
  const members = Object.keys(record)
    .sort() // default sort compares UTF-16 code units — the RFC 8785 §3.2.3 order
    .map((key) => {
      const member = record[key];
      if (member === undefined) {
        throw new CanonicalizationError(
          `undefined member "${key}" cannot be canonicalized`,
        );
      }
      return `${serializeString(key)}:${canonicalizeAtDepth(member, depth + 1)}`;
    });
  return `{${members.join(",")}}`;
}

const encoder = new TextEncoder();

/** Canonical UTF-8 bytes of a JSON value — the exact bytes that get hashed/signed. */
export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value));
}
