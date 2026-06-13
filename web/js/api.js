/**
 * POST /authorize client — same-origin, no framework.
 *
 * The classification mirrors the service's error ≠ deny contract (DT1 + DX9):
 *   - "decision":      HTTP 200 + a body carrying decision AND the signed
 *                      evidence_artifact. ONLY this outcome may render a
 *                      certificate — no envelope, no certificate.
 *   - "problem":       an RFC 9457 problem+json document (4xx/5xx). An
 *                      integration failure; never signed, never a decision.
 *   - "network-error": the request never produced an HTTP response.
 *   - "unexpected":    anything else — treated as a system error by the UI,
 *                      NEVER as a decision.
 */

/** After this many ms in flight, the UI swaps to the "still waiting" copy. */
export const SLOW_THRESHOLD_MS = 2000;

const DECISIONS = new Set(["allow", "review", "deny"]);

/**
 * Classify an /authorize HTTP response. Pure — exhaustively unit-tested.
 * @param {number} status
 * @param {string} contentType
 * @param {unknown} body parsed JSON body (or null if unparseable)
 * @returns {{kind:string} & Record<string, any>}
 */
export function classifyOutcome(status, contentType, body) {
  const record = body !== null && typeof body === "object" && !Array.isArray(body)
    ? /** @type {Record<string, unknown>} */ (body)
    : null;

  if (status === 200 && record !== null) {
    // A certificate requires a SIGNED envelope: decision + evidence_artifact.
    // A 200 without the artifact is not a decision we can show as one.
    if (
      typeof record.decision === "string" &&
      DECISIONS.has(record.decision) &&
      typeof record.evidence_artifact === "string" &&
      record.evidence_artifact !== ""
    ) {
      return { kind: "decision", body: record };
    }
    return { kind: "unexpected", status, body };
  }

  if (contentType.includes("application/problem+json") && record !== null) {
    return { kind: "problem", status, problem: record };
  }

  return { kind: "unexpected", status, body };
}

/**
 * Send a payment intent to POST /authorize and classify the outcome.
 * @param {unknown} intent
 * @param {{ fetchImpl?: typeof fetch, baseUrl?: string, signal?: AbortSignal }} [options]
 * @returns {Promise<{kind:string} & Record<string, any>>}
 */
export async function authorizeIntent(intent, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const baseUrl = options.baseUrl ?? "";
  let response;
  try {
    response = await fetchImpl(`${baseUrl}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(intent),
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (error) {
    return {
      kind: "network-error",
      message: error instanceof Error ? error.message : String(error),
    };
  }

  let body;
  try {
    body = await response.json();
  } catch {
    body = null; // unparseable body — classified as "unexpected" below
  }
  const contentType = response.headers.get("content-type") ?? "";
  return classifyOutcome(response.status, contentType, body);
}
