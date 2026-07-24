import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  getWalletInstanceStatusHandler,
  walletInstanceStatusErrorSchema,
  walletInstanceStatusParamsSchema,
  walletInstanceStatusResponseSchema
} from '../handlers/get-wallet-instance.js';
import {
  registerWalletInstanceHandler,
  walletInstanceRegistrationErrorSchema,
  walletInstanceRegistrationRequestSchema
} from '../handlers/register-wallet-instance.js';
import {
  revokeWalletInstanceHandler,
  walletInstanceRevocationErrorSchema,
  walletInstanceRevocationParamsSchema,
  walletInstanceRevocationRequestSchema
} from '../handlers/revoke-wallet-instance.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstancesRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instances/:walletInstanceId',
    method: 'GET',
    schema: {
      operationId: 'getWalletInstanceStatus',
      summary: 'Retrieve Wallet Instance status',
      description: 'Returns status and registration metadata for a Wallet Instance visible to the authenticated user.',
      tags: ['Wallet Instance Management'],
      produces: ['application/json'],
      params: toFastifyJsonSchema(walletInstanceStatusParamsSchema),
      response: {
        200: {
          description: 'Wallet Instance status information.',
          ...toFastifyJsonSchema(walletInstanceStatusResponseSchema)
        },
        400: {
          description: 'Malformed Wallet Instance status retrieval request.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        401: {
          description: 'The request lacks valid authentication credentials.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        403: {
          description: 'The authenticated user cannot retrieve this Wallet Instance.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        404: {
          description: 'The Wallet Instance was not found.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        422: {
          description: 'The Wallet Instance identifier failed semantic validation.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        500: {
          description: 'Internal server error while retrieving Wallet Instance status.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        },
        503: {
          description: 'Wallet Instance status retrieval service is temporarily unavailable.',
          ...toFastifyJsonSchema(walletInstanceStatusErrorSchema)
        }
      }
    },
    handler: getWalletInstanceStatusHandler
  });

  app.route({
    url: '/wallet-instances/:walletInstanceId',
    method: 'PATCH',
    schema: {
      operationId: 'revokeWalletInstance',
      summary: 'Revoke a Wallet Instance',
      description: 'Revokes an active Wallet Instance visible to the authenticated user.',
      tags: ['Wallet Instance Management'],
      consumes: ['application/json'],
      produces: ['application/json'],
      params: toFastifyJsonSchema(walletInstanceRevocationParamsSchema),
      body: toFastifyJsonSchema(walletInstanceRevocationRequestSchema.partial().loose()),
      response: {
        400: {
          description: 'Malformed or incomplete Wallet Instance revocation request.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        401: {
          description: 'The request cannot be authenticated or authorized.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        403: {
          description: 'The authenticated user cannot revoke this Wallet Instance.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        404: {
          description: 'The Wallet Instance was not found.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        422: {
          description: 'The Wallet Instance revocation request failed semantic validation.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        500: {
          description: 'Internal server error while revoking Wallet Instance.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        },
        503: {
          description: 'Wallet Instance revocation service is temporarily unavailable.',
          ...toFastifyJsonSchema(walletInstanceRevocationErrorSchema)
        }
      }
    },
    handler: revokeWalletInstanceHandler
  });

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
