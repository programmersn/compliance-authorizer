/**
 * Dev boot: load the Shariah v0.1 demo pack, restore (or generate) the local
 * issuer key, start the API. SYNTHETIC DATA ONLY — this service must never
 * receive real card or customer data.
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
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
import { openEvidenceStore, type EvidenceStore } from "./store/index.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function loadOrCreateIssuerKey(): SigningKey {
  const keysDir = process.env["KEYS_DIR"] ?? join(repoRoot, ".keys");
  const keyPath = join(keysDir, "issuer.jwk.json");
  if (existsSync(keyPath)) {
    try {
      return importPrivateJwk(
        JSON.parse(readFileSync(keyPath, "utf8")) as PrivateJwk,
      );
    } catch (cause) {
      // A truncated write or a hand-edit leaves an unparseable/invalid JWK. Surface
      // an actionable message instead of a raw SyntaxError — this is a dev keystore,
      // so deleting it regenerates a fresh key on the next boot.
      throw new Error(
        `issuer keystore at ${keyPath} is unreadable or corrupt; delete it to regenerate a fresh dev key`,
        { cause },
      );
    }
  }
  const key = generateSigningKey();
  mkdirSync(keysDir, { recursive: true });
  // Atomic write: serialize to a temp file in the SAME directory, then rename over
  // the target (renameSync is atomic on a single volume on POSIX and Windows), so a
  // crash mid-write can never leave a half-written keystore behind. This assumes a
  // SINGLE instance (the dev/demo model): concurrent first-boots could each mint a
  // key and race on the rename — a multi-replica deployment would need exclusive
  // create + read-the-winner (W2 scope).
  // mode 0o600 is POSIX-only; on Windows it is a no-op (no ACL is applied), so the
  // dev keystore there relies on .gitignore (.keys/) and a single-user machine.
  const tempPath = `${keyPath}.${process.pid}.tmp`;
  writeFileSync(tempPath, JSON.stringify(exportPrivateJwk(key), null, 2), {
    mode: 0o600,
  });
  renameSync(tempPath, keyPath);
  return key;
}

/**
 * Open the file-backed evidence store (ET14) under a gitignored `data/` dir
 * (override with EVIDENCE_DB). On Node >= 22.6 the built-in `node:sqlite` backs
 * it with no dependency; openEvidenceStore() fails CLOSED with one instructive
 * message if no SQLite engine is available (it also names the better-sqlite3
 * fallback seam). Boot persists one observational row per issued decision; this
 * never changes the API's responses or determinism.
 */
async function openIssuerEvidenceStore(): Promise<EvidenceStore> {
  // An empty or whitespace-only EVIDENCE_DB is treated as UNSET (fall back to the
  // default path), never as an explicit path: node:sqlite reads "" as a throwaway
  // temporary database, so accepting it would SILENTLY discard every persisted
  // decision on shutdown. An override must name a real file.
  const envDbPath = process.env["EVIDENCE_DB"]?.trim();
  const dbPath = envDbPath ? envDbPath : join(repoRoot, "data", "evidence.sqlite");
  mkdirSync(dirname(dbPath), { recursive: true });
  return openEvidenceStore(dbPath);
}

/**
 * Resolve the listen port. Unset/empty/whitespace falls back to the default;
 * anything else MUST be an integer in [1, 65535]. Crucially, never let Number("")
 * → 0 silently bind a random ephemeral port — fail loudly instead.
 */
function parsePort(): number {
  const raw = process.env["PORT"];
  if (raw === undefined || raw.trim() === "") return 8787;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write(
      `compliance-authorizer: PORT must be an integer in [1, 65535] (got ${JSON.stringify(raw)})\n`,
    );
    process.exit(1);
  }
  return port;
}

// Boot: load the pack, restore/generate the issuer key, open the evidence store,
// build the server. Any failure here (a corrupt keystore, no SQLite engine, …)
// must print ONE actionable operator line and exit — never crash with a raw
// stack trace. The store open is awaited, so the whole boot lives in async main.
let loadedPack: ReturnType<typeof loadRulePackFile>;
let signingKey: SigningKey;
let store: EvidenceStore;
let app: ReturnType<typeof buildServer>;
try {
  loadedPack = loadRulePackFile(
    join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
  );
  signingKey = loadOrCreateIssuerKey();
  store = await openIssuerEvidenceStore();
  app = buildServer({
    loadedPacks: [loadedPack],
    signingKey,
    store,
    // Key-rotation seam: once the keystore retains rotated-out keys, pass the
    // full historical public set here as `publishedKeys` so old envelopes stay
    // verifiable. Until then buildServer defaults to [signingKey.publicJwk].
    logger: true,
  });
} catch (error) {
  process.stderr.write(
    `compliance-authorizer: failed to start — ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
}

const port = parsePort();
try {
  await app.listen({ port, host: "127.0.0.1" });
  app.log.info(
    {
      rule_pack: `${loadedPack.pack.id}@${loadedPack.pack.version}`,
      rule_pack_hash: loadedPack.hash,
      issuer_kid: signingKey.kid,
      issuer_did: signingKey.did,
    },
    "compliance-authorizer up — synthetic demo rule pack (UNCERTIFIED)",
  );
} catch (error: unknown) {
  app.log.error(error);
  process.exit(1);
}
