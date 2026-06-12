/**
 * Type declarations for inpage-verify.js (plain browser JS; tests import it
 * with types — same pattern as verifier/verify.d.mts).
 */
export function b64urlToBytes(text: string): Uint8Array;
export function bytesToB64url(bytes: Uint8Array): string;

export function parseCompactJws(jws: string): {
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  header: { alg: "EdDSA"; kid: string };
};

export function decodeEnvelope(jws: string): unknown;

export function sha256HexOfText(text: string): Promise<string>;

export function computeOkpThumbprint(x: string): Promise<string>;

export interface InPageVerdict {
  ok: boolean;
  kid?: string;
  reason?: string;
  unsupported?: boolean;
}

export function verifyEnvelopeSignature(
  jws: string,
  jwks: { keys?: unknown[] },
): Promise<InPageVerdict>;
