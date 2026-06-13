/**
 * Type declarations for api.js (plain browser JS; tests import it with types —
 * same pattern as verifier/verify.d.mts).
 */
export const SLOW_THRESHOLD_MS: number;

export type AuthorizeOutcome =
  | { kind: "decision"; body: Record<string, unknown> }
  | { kind: "problem"; status: number; problem: Record<string, unknown> }
  | { kind: "network-error"; message: string }
  | { kind: "unexpected"; status: number; body: unknown };

export function classifyOutcome(
  status: number,
  contentType: string,
  body: unknown,
): AuthorizeOutcome;

export interface MinimalResponse {
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

export function authorizeIntent(
  intent: unknown,
  options?: {
    fetchImpl?: (url: string, init?: unknown) => Promise<MinimalResponse>;
    baseUrl?: string;
    signal?: unknown;
  },
): Promise<AuthorizeOutcome>;
