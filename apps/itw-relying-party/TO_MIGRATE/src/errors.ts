import { FastifyReply, FastifyRequest } from "fastify";

export class NotFoundError extends Error {
  constructor(description = "Resource not found") {
    super(description);
  }
}

export abstract class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly description: string,
  ) {
    super(description);
  }
}

export class BadRequestError extends HttpError {
  constructor(
    description = "Invalid credential presentation: it might be malformed or incomplete",
  ) {
    super(400, "invalid_request", description);
  }
}

export class ForbiddenError extends HttpError {
  constructor(
    description = "Invalid KB-JWT signature, incorrect nonce, or untrusted Issuer.",
  ) {
    super(403, "invalid_request", description);
  }
}

export const onError = (
  error: unknown,
  _: FastifyRequest,
  reply: FastifyReply,
): FastifyReply => {
  if (error instanceof HttpError) {
    return reply.status(error.status).send({
      error: error.code,
      error_description: error.description,
    });
  }

  const errorMessage =
    error instanceof Error && error.message
      ? error.message
      : "Internal Server Error";

  return reply.status(500).send({
    error: "server_error",
    error_description: errorMessage,
  });
};
