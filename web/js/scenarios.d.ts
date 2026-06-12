/**
 * Type declarations for scenarios.js (plain browser JS; tests import it with
 * types — same pattern as verifier/verify.d.mts).
 */
export interface PlaygroundScenario {
  id: string;
  label: string;
  note: string;
  intent: Record<string, unknown> & { profile: string };
}

export const SCENARIOS: readonly PlaygroundScenario[];

export function intentSummary(intent: Record<string, unknown>): string;
