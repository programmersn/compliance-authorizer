/**
 * Dev boot: load the Shariah v0.1 demo pack, restore (or generate) the local
 * issuer key, start the API. SYNTHETIC DATA ONLY — this service must never
 * receive real card or customer data.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  exportPrivateJwk,
  generateSigningKey,
  importPrivateJwk,
  type PrivateJwk,
  type SigningKey,
} from "./crypto/keys.ts";
import { loadRulePackFile } from "./rules/loader.ts";
import { buildServer } from "./server.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function loadOrCreateIssuerKey(): SigningKey {
  const keysDir = process.env["KEYS_DIR"] ?? join(repoRoot, ".keys");
  const keyPath = join(keysDir, "issuer.jwk.json");
  if (existsSync(keyPath)) {
    return importPrivateJwk(
      JSON.parse(readFileSync(keyPath, "utf8")) as PrivateJwk,
    );
  }
  const key = generateSigningKey();
  mkdirSync(keysDir, { recursive: true });
  writeFileSync(keyPath, JSON.stringify(exportPrivateJwk(key), null, 2), {
    mode: 0o600,
  });
  return key;
}

const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = loadOrCreateIssuerKey();

const app = buildServer({
  loadedPacks: [loadedPack],
  signingKey,
  logger: true,
});

const port = Number(process.env["PORT"] ?? 8787);
app
  .listen({ port, host: "127.0.0.1" })
  .then(() => {
    app.log.info(
      {
        rule_pack: `${loadedPack.pack.id}@${loadedPack.pack.version}`,
        rule_pack_hash: loadedPack.hash,
        issuer_kid: signingKey.kid,
        issuer_did: signingKey.did,
      },
      "compliance-authorizer up — synthetic demo rule pack (UNCERTIFIED)",
    );
  })
  .catch((error: unknown) => {
    app.log.error(error);
    process.exit(1);
  });
