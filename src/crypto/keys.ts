/**
 * Ed25519 issuer keys: generation, JWK export, RFC 7638 thumbprint (kid),
 * and did:key encoding (multicodec ed25519-pub 0xed01, multibase base58btc).
 *
 * did:key is the scholar-signature identifier format locked by the eng review
 * (D3); the issuer key reuses the same encoding so one code path is tested.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { sha256Base64Url } from "./hash.ts";

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  alg: "EdDSA";
  use: "sig";
}

export interface PrivateJwk extends PublicJwk {
  d: string;
}

export interface SigningKey {
  privateKey: KeyObject;
  publicJwk: PublicJwk;
  kid: string;
  did: string;
}

/**
 * RFC 7638 JWK thumbprint for an OKP key: SHA-256 over the JSON object holding
 * ONLY the required members, in lexicographic order: {"crv","kty","x"}.
 */
export function computeKid(x: string): string {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(x)}}`;
  return sha256Base64Url(canonical);
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const byte of bytes) n = n * 256n + BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = BASE58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  // Leading zero bytes encode as leading '1's.
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function base58btcDecode(text: string): Uint8Array {
  let n = 0n;
  for (const char of text) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`invalid base58btc character: ${char}`);
    n = n * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const char of text) {
    if (char !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** Multicodec prefix for ed25519-pub: varint 0xed → bytes 0xed 0x01. */
const ED25519_PUB_MULTICODEC = Uint8Array.from([0xed, 0x01]);

/** Encode a raw 32-byte Ed25519 public key as a did:key DID. */
export function didKeyFromRawPublicKey(raw: Uint8Array): string {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  const prefixed = new Uint8Array(ED25519_PUB_MULTICODEC.length + raw.length);
  prefixed.set(ED25519_PUB_MULTICODEC, 0);
  prefixed.set(raw, ED25519_PUB_MULTICODEC.length);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

/** Decode a did:key DID back to the raw 32-byte Ed25519 public key. */
export function rawPublicKeyFromDidKey(did: string): Uint8Array {
  if (!did.startsWith("did:key:z")) {
    throw new Error("not a multibase base58btc did:key");
  }
  const prefixed = base58btcDecode(did.slice("did:key:z".length));
  if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) {
    throw new Error("did:key does not carry an ed25519-pub multicodec prefix");
  }
  const raw = prefixed.slice(2);
  if (raw.length !== 32) {
    throw new Error(`expected 32 key bytes, got ${raw.length}`);
  }
  return raw;
}

function publicJwkFromKeyObjects(publicKey: KeyObject): PublicJwk {
  const exported = publicKey.export({ format: "jwk" }) as {
    kty?: string;
    crv?: string;
    x?: string;
  };
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || !exported.x) {
    throw new Error("expected an Ed25519 OKP public key");
  }
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: exported.x,
    kid: computeKid(exported.x),
    alg: "EdDSA",
    use: "sig",
  };
}

/** Generate a fresh Ed25519 signing key with its public JWK, kid, and did:key. */
export function generateSigningKey(): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicJwkFromKeyObjects(publicKey);
  return {
    privateKey,
    publicJwk,
    kid: publicJwk.kid,
    did: didKeyFromRawPublicKey(Buffer.from(publicJwk.x, "base64url")),
  };
}

/** Export the private key as a JWK for the local dev keystore (never commit). */
export function exportPrivateJwk(key: SigningKey): PrivateJwk {
  const exported = key.privateKey.export({ format: "jwk" }) as { d?: string };
  if (!exported.d) throw new Error("private key export missing 'd'");
  return { ...key.publicJwk, d: exported.d };
}

/** Restore a SigningKey from a stored private JWK. */
export function importPrivateJwk(jwk: PrivateJwk): SigningKey {
  const privateKey = createPrivateKey({
    key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d },
    format: "jwk",
  });
  // Prove the stored public `x` actually corresponds to the private `d`. Node does
  // NOT cross-check them on import (verified empirically), so a mismatched or
  // hand-edited keystore would sign with `d` while we publish the kid/DID derived
  // from `x` — every resulting envelope would then fail verification. Fail closed
  // instead, in the same spirit as the loader: a bad input never loads.
  const derivedX = (
    createPublicKey(privateKey).export({ format: "jwk" }) as { x?: string }
  ).x;
  if (derivedX !== jwk.x) {
    throw new Error(
      "private key 'd' does not correspond to public 'x' in the stored JWK",
    );
  }
  const publicJwk: PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    kid: computeKid(jwk.x),
    alg: "EdDSA",
    use: "sig",
  };
  return {
    privateKey,
    publicJwk,
    kid: publicJwk.kid,
    did: didKeyFromRawPublicKey(Buffer.from(jwk.x, "base64url")),
  };
}

/** RFC 7517 JWKS document carrying every historical public key. */
export function buildJwks(keys: readonly PublicJwk[]): { keys: PublicJwk[] } {
  return { keys: [...keys] };
}
