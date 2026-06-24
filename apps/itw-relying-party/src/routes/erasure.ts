import { z } from 'zod';

import type { FastifyPluginAsync } from 'fastify';

const erasureRequestSchema = z.object({
  attributes: z.array(z.string().trim().min(1)).min(1),
  callback_uri: z.string().trim().url(),
  state: z.string().trim().uuid()
});

const erasureCallbackSchema = z.object({
  outcome: z.enum(['rejected', 'success']),
  redirect_uri: z.string().trim().url().optional(),
  state: z.string().trim().uuid()
});

const erasureQuerySchema = z.object({
  callback_uri: z.string().trim().url(),
  state: z.string().trim().uuid()
});

function buildCallbackUri(callbackUri: string, state: string): string {
  const callbackUrl = new URL(callbackUri);
  callbackUrl.searchParams.set('state', state);
  return callbackUrl.toString();
}

const erasureRoute: FastifyPluginAsync = async (app) => {
  app.get('/auth/erasure', { schema: { tags: ['Relying Party'] } }, async (request, reply) => {
    const parsed = erasureQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ message: 'Invalid erasure redirect query' });
    }

    const session = await app.sessionService.get(parsed.data.state);
    if (session === undefined) {
      return reply.code(404).send({ message: 'Session not found' });
    }

    return reply.code(200).send({ callback_uri: buildCallbackUri(parsed.data.callback_uri, parsed.data.state) });
  });

  app.post('/auth/erasure', { schema: { tags: ['Relying Party'] } }, async (request, reply) => {
    const parsed = erasureRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ message: 'Invalid erasure request payload' });
    }

    const session = await app.sessionService.get(parsed.data.state);
    if (session === undefined) {
      return reply.code(404).send({ message: 'Session not found' });
    }

    await app.sessionService.update(parsed.data.state, 'checking');

    app.log.info(
      {
        attributes: parsed.data.attributes,
        rpId: app.config.entityId,
        state: parsed.data.state,
        timestamp: new Date().toISOString()
      },
      'Erasure request received'
    );

    return reply.code(200).send({ callback_uri: buildCallbackUri(parsed.data.callback_uri, parsed.data.state) });
  });

  app.post('/auth/erasure/callback', { schema: { tags: ['Relying Party'] } }, async (request, reply) => {
    const parsed = erasureCallbackSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ message: 'Invalid erasure callback payload' });
    }

    const session = await app.sessionService.get(parsed.data.state);
    if (session === undefined) {
      return reply.code(404).send({ message: 'Session not found' });
    }

    if (parsed.data.outcome === 'success') {
      const redirectUri = parsed.data.redirect_uri ?? 'success.html?response_code=success';
      await app.sessionService.update(parsed.data.state, 'verified', { redirectUri });
      return reply.code(200).send({ redirect_uri: redirectUri });
    }

    await app.sessionService.update(parsed.data.state, 'rejected');
    return reply.code(200).send({ redirect_uri: 'rejected-error.html?response_code=rejected' });
  });
};

export default erasureRoute;
