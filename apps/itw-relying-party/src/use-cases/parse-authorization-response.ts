import { z } from 'zod';

const responseBodySchema = z
  .object({
    error: z
      .enum([
        'invalid_request_object',
        'invalid_request_uri',
        'vp_formats_not_supported',
        'invalid_request',
        'access_denied',
        'invalid_client'
      ])
      .optional(),
    error_description: z.string().optional(),
    response: z.string().optional(),
    state: z.string().optional()
  })
  .refine(
    (data) =>
      (data.response !== undefined && data.error === undefined && data.state === undefined) ||
      (data.response === undefined && data.error !== undefined && data.state !== undefined),
    {
    message: "Either 'response' or 'error, state' must be present"
    }
  );

export class ParseAuthorizationResponseError extends Error {
  readonly statusCode = 400;

  constructor() {
    super('The request is missing required parameters');
    this.name = 'ParseAuthorizationResponseError';
  }
}

export type ParsedAuthorizationResponse =
  | {
      kind: 'oauth-error';
      error: NonNullable<z.infer<typeof responseBodySchema>['error']>;
      errorDescription?: string;
      state: string;
    }
  | {
      kind: 'jarm';
      response: string;
    };

export function parseAuthorizationResponseUseCase(rawBody: unknown): ParsedAuthorizationResponse {
  const parsed = responseBodySchema.safeParse(rawBody);
  if (!parsed.success) {
    throw new ParseAuthorizationResponseError();
  }

  if (parsed.data.response !== undefined) {
    return {
      kind: 'jarm',
      response: parsed.data.response
    };
  }

  if (!parsed.data.error || !parsed.data.state) {
    throw new ParseAuthorizationResponseError();
  }

  return {
    kind: 'oauth-error',
    error: parsed.data.error,
    errorDescription: parsed.data.error_description,
    state: parsed.data.state
  };
}
