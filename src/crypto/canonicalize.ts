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
 * Serialize a JSON-compatible value to its RFC 8785 canonical form.
 *
 * - Object members are sorted by UTF-16 code units of their names (§3.2.3),
 *   which is exactly ECMAScript's default string sort order.
 * - Strings and finite numbers are serialized via JSON.stringify, which RFC 8785
 *   defines as the normative serialization (§3.2.2.1, §3.2.2.3) — including
 *   -0 → "0" and shortest-round-trip number formatting.
 */
export function canonicalize(value: unknown): string {
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
      return JSON.stringify(value);
    case "object":
      break; // handled below
    default:
      throw new CanonicalizationError(
        `value of type "${typeof value}" cannot be canonicalized`,
      );
  }

  if (Array.isArray(value)) {
    return `[${value.map((element) => canonicalize(element)).join(",")}]`;
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
      return `${JSON.stringify(key)}:${canonicalize(member)}`;
    });
  return `{${members.join(",")}}`;
}

/** Canonical UTF-8 bytes of a JSON value — the exact bytes that get hashed/signed. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
