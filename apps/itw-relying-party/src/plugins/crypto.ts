import {
  createDecryptJweCallback,
  createEncryptJweCallback,
  createSignJwtCallback
} from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { CallbackContext } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  export interface FastifyInstance {
    callbacks: CallbackContext;
  }
}

const cryptoPlugin: FastifyPluginAsync = async (app) => {
  const callbacks = {
    ...partialCallbacks,
    decryptJwe: createDecryptJweCallback(app.jwks.enc.private),
    encryptJwe: createEncryptJweCallback(app.jwks.enc.public),
    fetch,
    signJwt: createSignJwtCallback([app.jwks.sig.private])
  };

  // @ts-expect-error - SDK bug related to authorizationServerMetadata
  app.decorate('callbacks', callbacks);
};

export default fp(cryptoPlugin, {
  name: 'crypto-plugin',
  dependencies: ['jwk-plugin']
});
