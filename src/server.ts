import Fastify, { type FastifyInstance } from "fastify";
import { assertPublishableJwk } from "./crypto/keys.ts";
import type { PublicJwk, SigningKey } from "./crypto/keys.ts";
import type { EnvelopeDeps } from "./evidence/envelope.ts";
import { registerProblemHandling } from "./http/problem.ts";
import { authorizeRoute } from "./routes/authorize.ts";
import { jwksRoute } from "./routes/jwks.ts";
import { rulePacksRoute } from "./routes/rule-packs.ts";
import { verifyRoute } from "./routes/verify.ts";
import type { LoadedRulePack } from "./rules/loader.ts";

export interface ServerOptions {
  loadedPacks: readonly LoadedRulePack[];
  signingKey: SigningKey;
  /**
   * Key-rotation seam: the FULL set of historical public verifying keys to
   * publish at JWKS, so any envelope ever signed by this engine stays
   * offline-verifiable by kid. Defaults to just the current signer's public
   * JWK — keeps every existing caller working. `signingKey` remains the
   * CURRENT signer used by /authorize.
   */
  publishedKeys?: readonly PublicJwk[];
  envelopeDeps?: EnvelopeDeps;
  logger?: boolean;
}

export function buildServer(options: ServerOptions): FastifyInstance {
  const app = Fastify({
    logger: options.logger ?? false,
    // Pin the request-body bound in-repo rather than relying on the Fastify
    // default staying 1 MiB across majors — the per-request canonicalization
    // cost ceiling and the 413 contract both assume exactly this value.
    bodyLimit: 1_048_576,
    ajv: {
      customOptions: {
        // A compliance API must never decide on silently-repaired input:
        // no type coercion, no stripping of unknown fields, no defaults.
        coerceTypes: false,
        removeAdditional: false,
        useDefaults: false,
      },
    },
  });

  registerProblemHandling(app);

  // Key-rotation seam: default to publishing only the current signer's public
  // key, so every existing caller keeps working unchanged. A rotating deployment
  // passes the full historical set here while `signingKey` stays the live signer.
  const publishedKeys = options.publishedKeys ?? [options.signingKey.publicJwk];

  // Snapshot the published set into FROZEN, fully-projected public JWKs — one read
  // per field, taken once here at boot. `publishedKeys` is the caller's array and
  // its members may be live objects; the routes below hold this set for the whole
  // process lifetime and re-read its fields on every JWKS / verify request. Without
  // the snapshot, a post-boot mutation of that array — or a hostile getter on a
  // member — could publish an unimportable key, drop the live signer, or desync
  // JWKS from /verify AFTER the boot guards already passed. We validate and serve
  // the SAME frozen bytes. (Same read-once posture as verifyCompact's per-key
  // snapshot in jws.ts.)
  const publishedSnapshot: readonly PublicJwk[] = Object.freeze(
    publishedKeys.map((jwk) =>
      Object.freeze({
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        kid: jwk.kid,
        alg: jwk.alg,
        use: jwk.use,
      }),
    ),
  );

  // Fail closed on a malformed published key — same no-silent-repair posture as
  // the loader and importPrivateJwk (keys.ts). The JWKS endpoint is a STRUCTURAL
  // projector (RFC 7517 shape + no private `d`), not a semantic validator, so the
  // value-integrity invariant it relies on — every kid IS the RFC 7638 thumbprint
  // of a real, IMPORTABLE Ed25519 signing key — is asserted HERE, at the boot
  // boundary, rather than served verbatim. A historical key set with a swapped,
  // relabeled, or structurally-broken entry must refuse to boot, never publish a
  // key an independent verifier would reject.
  for (const jwk of publishedSnapshot) {
    assertPublishableJwk(jwk);
  }

  // The live signer's OWN verifying key must be in the published set. A rotation
  // config that omits it would let /authorize emit 200 signed decisions that this
  // engine's own JWKS — and POST /verify, which resolves keys from this set — then
  // REJECT (kid not found), silently breaking the product's core promise that every
  // decision is independently verifiable. The default set is exactly
  // [signingKey.publicJwk]; only a deployment passing `publishedKeys` can violate
  // this, so guard it at boot rather than discover it per failed verification.
  if (!publishedSnapshot.some((jwk) => jwk.kid === options.signingKey.kid)) {
    throw new Error(
      `the live signing key (kid ${options.signingKey.kid}) is not among ` +
        `publishedKeys — its decisions would fail this engine's own JWKS and ` +
        `/verify; refusing to boot`,
    );
  }

  // A profile collision is a boot failure, never a silent last-wins overwrite —
  // same principle as the loader: a misconfigured pack set must refuse to serve.
  // This guard runs FIRST: passing the same pack twice collides on profile here.
  const packsByProfile = new Map<string, LoadedRulePack>();
  for (const loaded of options.loadedPacks) {
    if (packsByProfile.has(loaded.pack.profile)) {
      throw new Error(
        `duplicate rule-pack profile "${loaded.pack.profile}" — refusing to boot`,
      );
    }
    packsByProfile.set(loaded.pack.profile, loaded);
  }

  // Second, independent index: rule packs keyed by `${id}/${version}` so a
  // consumer can fetch the exact pack a given envelope was decided against
  // (two distinct profiles could share an id at different versions). Its own
  // duplicate guard — also a boot failure — with a distinct message.
  const packsByIdVersion = new Map<string, LoadedRulePack>();
  for (const loaded of options.loadedPacks) {
    const key = `${loaded.pack.id}/${loaded.pack.version}`;
    if (packsByIdVersion.has(key)) {
      throw new Error(
        `duplicate rule-pack id/version "${key}" — refusing to boot`,
      );
    }
    packsByIdVersion.set(key, loaded);
  }

  void app.register(authorizeRoute, {
    packsByProfile,
    signingKey: options.signingKey,
    ...(options.envelopeDeps ? { envelopeDeps: options.envelopeDeps } : {}),
  });

  // W2 routes — pre-wired here so the fan-out implementers inherit a stable
  // seam; each plugin receives ONLY what it needs.
  void app.register(jwksRoute, { publishedKeys: publishedSnapshot });
  void app.register(rulePacksRoute, { packsByIdVersion });
  void app.register(verifyRoute, { publishedKeys: publishedSnapshot, packsByIdVersion });

  return app;
}
