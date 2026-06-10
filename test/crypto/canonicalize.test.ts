/**
 * RFC 8785 (JCS) conformance — test vectors quoted from the RFC itself
 * (fetched from rfc-editor.org, not reconstructed from memory).
 *
 * Control characters are built with String.fromCharCode so no raw control
 * bytes or ambiguous escapes live in this source file.
 */
import { describe, expect, it } from "vitest";
import {
  CanonicalizationError,
  canonicalize,
} from "../../src/crypto/canonicalize.ts";

const BS = "\\"; // one backslash
const SHIFT_IN = String.fromCharCode(0x0f); // U+000F (no two-char JSON escape)
const NEWLINE = String.fromCharCode(0x0a); // U+000A
const CR = String.fromCharCode(0x0d); // U+000D
const CTRL_80 = String.fromCharCode(0x80); // U+0080

describe("RFC 8785 test vectors", () => {
  it("canonicalizes the RFC 8785 §3.2.3 sample document exactly", () => {
    // Input string decodes to: € $ U+000F U+000A A ' B " \ \ " /
    const sample = `€$${SHIFT_IN}${NEWLINE}A'B"${BS}${BS}"/`;
    const input = {
      // eslint-disable-next-line no-loss-of-precision -- literal RFC 8785 vector; normalizing to the nearest double is the point
      numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
      string: sample,
      literals: [null, true, false],
    };
    // Expected canonical text from the RFC:
    // {"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,
    //  0.002,1e-27],"string":"€$\nA'B\"\\\\\"/"}
    const expectedString =
      `"€$` + BS + `u000f` + BS + `nA'B` + BS + `"` + BS + BS + BS + BS + BS + `"/"`;
    const expected =
      `{"literals":[null,true,false],` +
      `"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
      `"string":${expectedString}}`;
    expect(canonicalize(input)).toBe(expected);
  });

  it("serializes numbers per the RFC 8785 Appendix B vectors", () => {
    expect(canonicalize(0)).toBe("0");
    expect(canonicalize(-0)).toBe("0"); // minus zero collapses to "0"
    expect(canonicalize(5e-324)).toBe("5e-324"); // min positive double
    expect(canonicalize(1.7976931348623157e308)).toBe("1.7976931348623157e+308"); // max double
    // eslint-disable-next-line no-loss-of-precision -- literal RFC 8785 vector
    expect(canonicalize(333333333.33333329)).toBe("333333333.3333333");
    expect(canonicalize(1e30)).toBe("1e+30");
    expect(canonicalize(4.5)).toBe("4.5");
    expect(canonicalize(2e-3)).toBe("0.002");
    expect(canonicalize(1e-27)).toBe("1e-27");
  });

  it("sorts properties by UTF-16 code units (RFC 8785 §3.2.3 unicode vector)", () => {
    // Keys built from explicit code units so no editor/encoding normalization
    // can change what is being tested (the dalet MUST be precomposed U+FB33).
    const EURO = String.fromCharCode(0x20ac);
    const O_DIAERESIS = String.fromCharCode(0xf6);
    const DALET_DAGESH = String.fromCharCode(0xfb33);
    const EMOJI = String.fromCharCode(0xd83d, 0xde00); // surrogate pair
    const input: Record<string, string> = {
      [EURO]: "Euro Sign",
      [CR]: "Carriage Return",
      [DALET_DAGESH]: "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      [EMOJI]: "Emoji: Grinning Face",
      [CTRL_80]: "Control",
      [O_DIAERESIS]: "Latin Small Letter O With Diaeresis",
    };
    // Expected order straight from the RFC:
    // \r, "1", U+0080, ö, €, 😀 (surrogate pair d83d de00), dalet (fb33).
    const expectedOrder = [CR, "1", CTRL_80, O_DIAERESIS, EURO, EMOJI, DALET_DAGESH];
    const expected = `{${expectedOrder
      .map((key) => `${JSON.stringify(key)}:${JSON.stringify(input[key])}`)
      .join(",")}}`;
    expect(canonicalize(input)).toBe(expected);
  });
});

describe("canonicalization invariance", () => {
  it("is independent of property insertion order", () => {
    const a = { z: 1, a: { y: true, b: [1, 2, 3] }, m: "x" };
    const b = { m: "x", a: { b: [1, 2, 3], y: true }, z: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it("is invariant under pretty-print round-trips (whitespace never matters)", () => {
    const value = { rules: [{ id: "R1", t: 0.05 }], name: "pack" };
    const pretty = JSON.stringify(value, null, 4);
    expect(canonicalize(JSON.parse(pretty))).toBe(canonicalize(value));
  });
});

describe("strictness — hash inputs are never guessed", () => {
  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
  ])("throws on non-finite number %s", (_label, value) => {
    expect(() => canonicalize(value)).toThrow(CanonicalizationError);
  });

  it("throws on undefined object members instead of dropping them", () => {
    expect(() => canonicalize({ a: undefined })).toThrow(CanonicalizationError);
  });

  it("throws on undefined array elements instead of nulling them", () => {
    expect(() => canonicalize([1, undefined, 3])).toThrow(CanonicalizationError);
  });

  it("throws on non-JSON types (bigint, function, symbol)", () => {
    expect(() => canonicalize(1n)).toThrow(CanonicalizationError);
    expect(() => canonicalize(() => 1)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Symbol("x"))).toThrow(CanonicalizationError);
  });

  it("throws on class instances instead of silently coercing them", () => {
    expect(() => canonicalize(new Date(0))).toThrow(CanonicalizationError);
    expect(() => canonicalize(new Map())).toThrow(CanonicalizationError);
  });

  it("accepts null-prototype objects (plain JSON data)", () => {
    const value = Object.create(null) as Record<string, unknown>;
    value["a"] = 1;
    expect(canonicalize(value)).toBe('{"a":1}');
  });

  it("throws beyond the nesting depth bound instead of overflowing the stack", () => {
    const deep: unknown = JSON.parse("[".repeat(300) + "1" + "]".repeat(300));
    expect(() => canonicalize(deep)).toThrow(CanonicalizationError);
    expect(() => canonicalize(deep)).toThrow(/depth bound/);
    // ...while legitimate nesting depths stay accepted.
    const shallow = "[".repeat(50) + "1" + "]".repeat(50);
    expect(canonicalize(JSON.parse(shallow))).toBe(shallow);
  });

  // RFC 8785 §3.2.2.2: invalid Unicode (a lone surrogate) MUST terminate the
  // canonicalizer. JSON.stringify would silently ESCAPE it as \udXXX (the
  // non-compliant ES2019 path strict external verifiers reject), so the
  // canonicalizer rejects it explicitly instead.
  it.each([
    ["a lone high surrogate value", String.fromCharCode(0xd800)],
    ["a lone low surrogate value", String.fromCharCode(0xdc00)],
    ["a lone surrogate inside a longer string", `ok${String.fromCharCode(0xd834)}bad`],
  ])("throws on %s instead of silently escaping it", (_label, value) => {
    expect(() => canonicalize(value)).toThrow(CanonicalizationError);
    expect(() => canonicalize(value)).toThrow(/lone UTF-16 surrogate/);
  });

  it("throws on a lone surrogate in an object KEY, not only a value", () => {
    expect(() => canonicalize({ [String.fromCharCode(0xd800)]: 1 })).toThrow(
      CanonicalizationError,
    );
  });

  it("ACCEPTS a valid surrogate pair — a LONE surrogate is the only rejected Unicode case", () => {
    const EMOJI = String.fromCharCode(0xd83d, 0xde00); // 😀 (a valid high+low pair)
    expect(canonicalize({ label: EMOJI })).toBe(`{"label":"${EMOJI}"}`);
  });
});
