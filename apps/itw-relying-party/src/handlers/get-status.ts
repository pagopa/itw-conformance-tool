import z from 'zod';

import type { FastifyRequest } from 'fastify';

export const getStatusParamsSchema = z.object({
  state: z.uuid().describe('Authorization request state identifier.')
});

export type GetStatusParams = z.infer<typeof getStatusParamsSchema>;

export const getStatusResponseSchema = z.object({
  redirect_uri: z
    .string()
    .describe('Relative or absolute URI the caller should navigate to for the current session status.'),
  values: z
    .array(z.record(z.string(), z.union([z.string(), z.null()])))
    .optional()
    .describe('Optional credential values returned after a verified presentation.')
});

export type GetStatusResponse = z.infer<typeof getStatusResponseSchema>;

export const getStatusHandler = async (
  req: FastifyRequest<{ Params: GetStatusParams }>
): Promise<GetStatusResponse> => {
  const { state } = req.params;
  const requestObjectRepository = req.server.repository.requestObject;

  const { redirectUri, status, values } = requestObjectRepository.get(state);

  switch (status) {
    case 'verified':
      if (!redirectUri) {
        requestObjectRepository.delete(state);

        return {
          redirect_uri: 'error.html?response_code=unexpected'
        };
      }

      return {
        redirect_uri: `${redirectUri}?response_code=success`,
        values
      };

    case 'rejected':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'rejected-error.html?response_code=rejected'
      };

    case 'denied':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'error.html?response_code=denied'
      };

    case 'expired':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'timeout.html?response_code=expired'
      };

    case 'checking':
      return {
        redirect_uri: '?response_code=checking'
      };

    default:
      return {
        redirect_uri: '?response_code=pending'
      };
  }
};
