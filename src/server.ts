import Fastify, { type FastifyInstance } from "fastify";
import type { SigningKey } from "./crypto/keys.ts";
import type { EnvelopeDeps } from "./evidence/envelope.ts";
import { registerProblemHandling } from "./http/problem.ts";
import { authorizeRoute } from "./routes/authorize.ts";
import type { LoadedRulePack } from "./rules/loader.ts";

export interface ServerOptions {
  loadedPacks: readonly LoadedRulePack[];
  signingKey: SigningKey;
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

  // A profile collision is a boot failure, never a silent last-wins overwrite —
  // same principle as the loader: a misconfigured pack set must refuse to serve.
  const packsByProfile = new Map<string, LoadedRulePack>();
  for (const loaded of options.loadedPacks) {
    if (packsByProfile.has(loaded.pack.profile)) {
      throw new Error(
        `duplicate rule-pack profile "${loaded.pack.profile}" — refusing to boot`,
      );
    }
    packsByProfile.set(loaded.pack.profile, loaded);
  }

  void app.register(authorizeRoute, {
    packsByProfile,
    signingKey: options.signingKey,
    ...(options.envelopeDeps ? { envelopeDeps: options.envelopeDeps } : {}),
  });

  return app;
}
