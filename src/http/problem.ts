/**
 * RFC 9457 problem+json for INTEGRATION FAILURES — the load-bearing half of
 * the error ≠ deny guard:
 *
 *   - a DECISION (allow / deny / review) is HTTP 200 + a SIGNED envelope;
 *   - an integration failure is a 4xx/5xx problem+json document and NEVER
 *     carries an evidence artifact — no envelope for a failure exists at all.
 *
 * Nothing in this module touches the signing key, by construction.
 */
import type {
  FastifyError,
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
} from "fastify";

export const PROBLEM_CONTENT_TYPE = "application/problem+json";

export interface ProblemDocument {
  type: string;
  title: string;
  status: number;
  detail: string;
  [extension: string]: unknown;
}

export class ProblemError extends Error {
  override name = "ProblemError";
  readonly status: number;
  readonly title: string;
  readonly detail: string;
  readonly problemType: string;
  readonly extensions: Record<string, unknown>;

  constructor(
    status: number,
    title: string,
    detail: string,
    problemType: string = "about:blank",
    extensions: Record<string, unknown> = {},
  ) {
    super(`${title}: ${detail}`);
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.problemType = problemType;
    this.extensions = extensions;
  }

  toDocument(): ProblemDocument {
    return {
      type: this.problemType,
      title: this.title,
      status: this.status,
      detail: this.detail,
      ...this.extensions,
    };
  }
}

function sendProblem(reply: FastifyReply, problem: ProblemDocument): void {
  void reply.status(problem.status).type(PROBLEM_CONTENT_TYPE).send(problem);
}

/** Render Fastify/AJV validation errors as an actionable problem document (DX9). */
function validationProblem(error: FastifyError): ProblemDocument {
  const issues = (error.validation ?? []).map((issue) => ({
    field: issue.instancePath === "" ? "(body root)" : issue.instancePath,
    message: issue.message ?? "invalid value",
    ...(issue.params && "allowedValues" in issue.params
      ? { allowed_values: issue.params["allowedValues"] }
      : {}),
  }));
  return {
    type: "https://github.com/nouaim/compliance-authorizer/problems/invalid-intent",
    title: "Payment intent failed schema validation",
    status: 400,
    detail:
      "The request body is not a valid payment intent. No decision was made and no evidence envelope exists for this request.",
    issues,
  };
}

export function registerProblemHandling(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error instanceof ProblemError) {
      sendProblem(reply, error.toDocument());
      return;
    }
    if (error.validation) {
      sendProblem(reply, validationProblem(error));
      return;
    }
    request.log.error(error);
    sendProblem(reply, {
      type: "about:blank",
      title: "Internal error",
      status: 500,
      detail:
        "The service failed to process the request. No decision was made and no evidence envelope exists for this request.",
    });
  });

  app.setNotFoundHandler((request: FastifyRequest, reply: FastifyReply) => {
    sendProblem(reply, {
      type: "about:blank",
      title: "Not found",
      status: 404,
      detail: `No route matches ${request.method} ${request.url}.`,
    });
  });
}
