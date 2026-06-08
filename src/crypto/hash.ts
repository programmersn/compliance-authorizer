import { createHash } from "node:crypto";

/** Lowercase hex SHA-256 of a string (UTF-8) or raw bytes. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Base64url (unpadded) SHA-256 of a string (UTF-8) or raw bytes. */
export function sha256Base64Url(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("base64url");
}
