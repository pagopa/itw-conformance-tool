import { registerAuthRequestConformanceHooks } from '../hooks/conformance.js';
import { serveAuthorizationRequestUseCase } from '../use-cases/serve-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

interface AuthRequestParams {
  state: string;
}

interface PostAuthRequestBody {
  wallet_metadata?: string;
  wallet_nonce?: string;
}

// Fields required in wallet_metadata per Section 10.1 of [OpenID4VP]
const REQUIRED_WALLET_METADATA_FIELDS = [
  'vp_formats_supported',
  'client_id_schemes_supported',
  'authorization_endpoint'
];

const authRequestRoute: FastifyPluginAsync = async (app) => {
  registerAuthRequestConformanceHooks(app);

  // Parse application/x-www-form-urlencoded bodies (used by WP_083 POST flow)
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    try {
      const result: Record<string, string> = {};
      for (const [key, value] of new URLSearchParams(body as string)) {
        result[key] = value;
      }
      done(null, result);
    } catch (err) {
      done(err as Error, undefined);
    }
  });

  const routeSchema = {
    tags: ['Relying Party'],
    params: {
      type: 'object',
      required: ['state'],
      properties: { state: { type: 'string' } }
    },
    response: {
      200: { type: 'string', description: 'Signed Request Object JWT' },
      400: { type: 'object', properties: { message: { type: 'string' } } },
      404: { type: 'object', properties: { message: { type: 'string' } } },
      410: { type: 'object', properties: { message: { type: 'string' } } }
    }
  };

  // WP_082: GET — wallet retrieves the signed Request Object JWT
  app.route<{ Params: AuthRequestParams }>({
    url: '/auth/request/:state',
    method: 'GET',
    schema: routeSchema,
    handler: async (request, reply) => {
      const { state } = request.params;
      const jwt = await serveAuthorizationRequestUseCase({ state, sessionService: app.sessionService });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });

  // WP_083: POST — wallet sends wallet_metadata + wallet_nonce, retrieves the signed Request Object JWT
  app.route<{ Params: AuthRequestParams; Body: PostAuthRequestBody }>({
    url: '/auth/request/:state',
    method: 'POST',
    schema: routeSchema,
    handler: async (request, reply) => {
      const { state } = request.params;
      const { wallet_metadata, wallet_nonce } = request.body ?? {};

      // WP_083c: wallet_nonce must be present
      if (!wallet_nonce) {
        return reply.code(400).send({ message: 'Missing wallet_nonce' });
      }

      // WP_083a: wallet_metadata must be valid JSON with required fields
      if (!wallet_metadata) {
        return reply.code(400).send({ message: 'Missing wallet_metadata' });
      }

      let metadata: Record<string, unknown>;
      try {
        metadata = JSON.parse(wallet_metadata) as Record<string, unknown>;
      } catch {
        return reply.code(400).send({ message: 'Invalid wallet_metadata JSON' });
      }

      const missingFields = REQUIRED_WALLET_METADATA_FIELDS.filter((f) => !(f in metadata));
      if (missingFields.length > 0) {
        return reply
          .code(400)
          .send({ message: `wallet_metadata missing required fields: ${missingFields.join(', ')}` });
      }

      const jwt = await serveAuthorizationRequestUseCase({ state, sessionService: app.sessionService });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });
};

export default authRequestRoute;
