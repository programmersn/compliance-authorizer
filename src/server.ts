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

  const packsByProfile = new Map<string, LoadedRulePack>(
    options.loadedPacks.map((loaded) => [loaded.pack.profile, loaded]),
  );

  void app.register(authorizeRoute, {
    packsByProfile,
    signingKey: options.signingKey,
    ...(options.envelopeDeps ? { envelopeDeps: options.envelopeDeps } : {}),
  });

  return app;
}
