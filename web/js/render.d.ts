/**
 * Type declarations for render.js. The implementation stays plain browser JS
 * (no build step); tests import it with types — same pattern as
 * verifier/verify.d.mts.
 *
 * The project compiles WITHOUT the TS DOM lib (server code), so the render
 * functions are declared against a minimal structural view of a DOM element;
 * the real happy-dom elements satisfy it at runtime.
 */
export interface DomNodeLike {
  readonly textContent: string | null;
  readonly outerHTML: string;
  readonly className: string;
  readonly isConnected: boolean;
  getAttribute(name: string): string | null;
  querySelector(selector: string): DomNodeLike | null;
  querySelectorAll(selector: string): ArrayLike<DomNodeLike> & Iterable<DomNodeLike>;
  compareDocumentPosition(other: DomNodeLike): number;
  readonly classList: { contains(token: string): boolean };
  readonly dataset: Record<string, string | undefined>;
}

export interface InputIssueLike {
  field?: string;
  message?: string;
  allowed_values?: unknown[];
}

export interface InputProblemLike {
  kind?: string;
  message?: string;
  detail?: string;
  issues?: InputIssueLike[];
}

export interface ProblemViewLike {
  title?: string;
  detail?: string;
  status?: number | null;
  type?: string;
  instance?: string;
}

export const REASON_LABELS: Record<string, string>;

export function renderEmptyShell(): DomNodeLike;
export function renderLoading(
  intent: Record<string, unknown>,
  phase?: "loading" | "slow",
): DomNodeLike;
export function renderCertificate(body: Record<string, unknown>): DomNodeLike;
export function renderProblemPanel(view: ProblemViewLike): DomNodeLike;
export function renderInputIssues(problem: InputProblemLike): DomNodeLike;
