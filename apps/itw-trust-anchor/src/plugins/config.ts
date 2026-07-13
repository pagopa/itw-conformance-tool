import { loadConfig } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      baseUrl: string;
      dataDir: string;
      issuerEntityId: string;
      rpEntityId: string;
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

// Every service (issuer, rp, trust-anchor) derives its own public OpenID Federation
// entity ID from its own [section].entity_id, falling back to its own local listen
// address only when entity_id is left blank. Applying this identical formula to the
// same raw config sections here guarantees the Trust Anchor resolves the exact same
// entity IDs that the issuer and rp resolve for themselves, without any runtime
// coupling between the apps.
function resolveEntityId(entityId: string, port: number): string {
  const trimmed = entityId.trim();
  return trimTrailingSlashes(trimmed.length > 0 ? trimmed : `https://localhost:${port}`);
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const trustAnchorConfig = config['itw-trust-anchor'];
    const issuerConfig = config['itw-credential-issuer'];
    const rpConfig = config.rp;

    app.decorate('config', {
      baseUrl: resolveEntityId(trustAnchorConfig.entity_id, trustAnchorConfig.port),
      dataDir: config.global.data_dir,
      issuerEntityId: resolveEntityId(issuerConfig.entity_id, issuerConfig.port),
      rpEntityId: resolveEntityId(rpConfig.entity_id, rpConfig.port)
    });
  },

  { name: 'config' }
);
