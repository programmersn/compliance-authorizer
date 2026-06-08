import Fastify, { type FastifyInstance } from "fastify";
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
  void app.register(jwksRoute, { publishedKeys });
  void app.register(rulePacksRoute, { packsByIdVersion });
  void app.register(verifyRoute, { publishedKeys, packsByIdVersion });

  return app;
}
