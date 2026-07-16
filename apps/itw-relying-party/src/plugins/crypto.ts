import fp from 'fastify-plugin';

import {
  getDecryptJweCallback,
  getEncryptJweCallback,
  getSignJwtCallback,
  callbacks as partialCallbacks
} from '../utils/crypto.js';

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
    decryptJwe: getDecryptJweCallback(app.jwks.enc.private),
    encryptJwe: getEncryptJweCallback(app.jwks.enc.public),
    fetch,
    signJwt: getSignJwtCallback([app.jwks.sig.private])
  };

  // @ts-expect-error - SDK bug related to authorizationServerMetadata
  app.decorate('callbacks', callbacks);
};

export default fp(cryptoPlugin, {
  name: 'crypto-plugin',
  dependencies: ['jwk-plugin']
});
