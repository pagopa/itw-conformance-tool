import { generateEcPrivateJwk } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { createTrustAnchorFaultStore, type TrustAnchorFaultStore } from '../domain/index.js';

import type { JwkKey } from './keys.js';

const WP_017_FAULT_KEY_ID = 'wp-017-nonmatching-trust-anchor-key';

declare module 'fastify' {
  interface FastifyInstance {
    trustAnchorFaultStore: TrustAnchorFaultStore;
    trustAnchorFaultKeys: {
      entityConfigurationNonmatchingSigningPrivateJwk: JwkKey;
    };
  }
}

async function publicThumbprint(jwk: JwkKey): Promise<string> {
  return calculateJwkThumbprint({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  } as JWK);
}

function generateFaultFederationPrivateJwk(): JwkKey {
  const jwks = generateEcPrivateJwk({
    alg: 'ES256',
    kid: WP_017_FAULT_KEY_ID,
    keyOps: ['sign'],
    use: 'sig'
  });

  const jwk = jwks.keys[0] as JwkKey | undefined;
  if (!jwk) throw new Error('Unable to generate the WP_017 Trust Anchor fault key');
  return jwk;
}

export default fp(
  async function trustAnchorFaultsPlugin(app) {
    const trustAnchorFaultStore = createTrustAnchorFaultStore();
    const nominalThumbprint = await publicThumbprint(app.trustAnchorKeys.federationPrivateJwk);
    const faultFederationPrivateJwk = generateFaultFederationPrivateJwk();
    const faultThumbprint = await publicThumbprint(faultFederationPrivateJwk);

    if (nominalThumbprint === faultThumbprint) {
      throw new Error('Generated WP_017 Trust Anchor fault key unexpectedly matches the nominal federation key');
    }

    app.decorate('trustAnchorFaultStore', trustAnchorFaultStore);
    app.decorate('trustAnchorFaultKeys', {
      entityConfigurationNonmatchingSigningPrivateJwk: faultFederationPrivateJwk
    });

    app.addHook('onClose', async () => {
      trustAnchorFaultStore.clear();
    });
  },
  { name: 'trust-anchor-faults', dependencies: ['keys'] }
);
