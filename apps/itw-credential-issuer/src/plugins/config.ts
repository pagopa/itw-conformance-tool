import { loadConfig, type IssuerAuthFlow } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: IssuerAuthFlow;
    };
  }
}

function trimTrailingSlashes(value: string): string {
  let result = value;
  while (result.endsWith('/')) {
    result = result.slice(0, -1);
  }
  return result;
}

// The issuer's public OpenID Federation entity ID must be stable and match what
// other services (e.g. the Trust Anchor) resolve for the same [itw-credential-issuer]
// config section, so it is derived from entity_id first, falling back to the local
// listen address only when entity_id is left blank.
function resolveBaseUrl(entityId: string, port: number): string {
  const trimmed = entityId.trim();
  return trimTrailingSlashes(trimmed.length > 0 ? trimmed : `https://localhost:${port}`);
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const issuerConfig = config['itw-credential-issuer'];

    app.decorate('config', {
      AUTH_FLOW: issuerConfig.auth_flow,
      BASE_URL: resolveBaseUrl(issuerConfig.entity_id, issuerConfig.port),
      DATA_DIR: config.global.data_dir
    });
  },

  { name: 'config' }
);
