import { z } from 'zod';

import type { FastifyPluginAsync } from 'fastify';
import type { FastifyReply } from 'fastify';

const erasureQuerySchema = z.object({
  attributes: z.union([z.string().trim(), z.array(z.string().trim())]).optional(),
  callback_url: z.string().trim().url(),
  state: z.string().trim().uuid()
});

function parseAttributes(input: string | string[] | undefined): string[] {
  if (input === undefined) {
    return [];
  }

  if (Array.isArray(input)) {
    return input
      .flatMap((attribute) => attribute.split(','))
      .map((attribute) => attribute.trim())
      .filter((attribute) => attribute.length > 0);
  }

  return input
    .split(',')
    .map((attribute) => attribute.trim())
    .filter((attribute) => attribute.length > 0);
}

function sendErasureError(
  reply: FastifyReply,
  statusCode: number,
  error: 'bad_request' | 'unauthorized' | 'server_error' | 'temporarily_unavailable',
  errorDescription: string
) {
  return reply.code(statusCode).type('application/json').send({
    error,
    error_description: errorDescription
  });
}

const erasureRoute: FastifyPluginAsync = async (app) => {
  app.get('/auth/erasure', { schema: { tags: ['Relying Party'] } }, async (request, reply) => {
    const parsed = erasureQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return sendErasureError(
        reply,
        400,
        'bad_request',
        'The request is malformed, missing required parameters, or includes invalid values.'
      );
    }

    try {
      const session = await app.sessionService.get(parsed.data.state);
      if (session === undefined) {
        return sendErasureError(reply, 400, 'bad_request', 'The request state is invalid, expired, or unknown.');
      }

      const attributes = parseAttributes(parsed.data.attributes);
      await app.sessionService.update(parsed.data.state, 'verified', { redirectUri: parsed.data.callback_url });

      app.log.info(
        {
          attributes,
          callbackUrl: parsed.data.callback_url,
          rpId: app.config.entityId,
          state: parsed.data.state,
          timestamp: new Date().toISOString()
        },
        'Erasure request received'
      );

      return reply.code(204).send();
    } catch (error) {
      app.log.error({ err: error }, 'Erasure request failed');
      return sendErasureError(
        reply,
        500,
        'server_error',
        'The request cannot be fulfilled due to an internal server error.'
      );
    }
  });
};

export default erasureRoute;
