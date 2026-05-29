import fp from 'fastify-plugin';

import { generateEphemeralKeyPair } from '../crypto/ephemeral-keys.js';

import type { EphemeralKeyPair } from '../crypto/ephemeral-keys.js';

declare module 'fastify' {
  interface FastifyInstance {
    ephemeralKeys: EphemeralKeyPair;
  }
}

export default fp(
  async function ephemeralKeysPlugin(app) {
    const keyPair = await generateEphemeralKeyPair();
    app.decorate('ephemeralKeys', keyPair);
  },
  { name: 'ephemeral-keys' }
);
