import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  registerWalletInstanceHandler,
  walletInstanceRegistrationErrorSchema,
  walletInstanceRegistrationRequestSchema
} from '../handlers/register-wallet-instance.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstancesRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instances',
    method: 'POST',
    schema: {
      operationId: 'registerWalletInstance',
      summary: 'Register a Wallet Instance',
      description:
        'Initializes a Wallet Instance by validating the nonce, Key Attestation, and Cryptographic Hardware Key tag.',
      tags: ['Wallet Instance Management'],
      consumes: ['application/json'],
      produces: ['application/json'],
      body: toFastifyJsonSchema(walletInstanceRegistrationRequestSchema.partial().loose()),
      response: {
        400: {
          description: 'Malformed or incomplete Wallet Instance registration request.',
          ...toFastifyJsonSchema(walletInstanceRegistrationErrorSchema)
        },
        403: {
          description: 'Wallet Instance registration rejected by nonce, attestation, or device integrity checks.',
          ...toFastifyJsonSchema(walletInstanceRegistrationErrorSchema)
        },
        422: {
          description: 'Wallet Instance registration request failed semantic validation.',
          ...toFastifyJsonSchema(walletInstanceRegistrationErrorSchema)
        },
        500: {
          description: 'Internal server error while processing Wallet Instance registration.',
          ...toFastifyJsonSchema(walletInstanceRegistrationErrorSchema)
        },
        503: {
          description: 'Wallet Instance registration service is temporarily unavailable.',
          ...toFastifyJsonSchema(walletInstanceRegistrationErrorSchema)
        }
      }
    },
    handler: registerWalletInstanceHandler
  });
};

export default walletInstancesRoute;
