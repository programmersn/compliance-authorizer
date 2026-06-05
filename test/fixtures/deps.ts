/**
 * Canonical deterministic envelope deps for tests: ONE fixed clock + UUID so
 * signed envelopes are byte-reproducible across test files. Change the
 * canonical fixture values here, nowhere else.
 */
import type { EnvelopeDeps } from "../../src/evidence/envelope.ts";

export const FIXED_TIMESTAMP = "2026-06-04T12:00:00.000Z";
export const FIXED_UUID = "11111111-2222-4333-8444-555555555555";

export const fixedEnvelopeDeps: EnvelopeDeps = {
  now: () => new Date(FIXED_TIMESTAMP),
  uuid: () => FIXED_UUID,
};
