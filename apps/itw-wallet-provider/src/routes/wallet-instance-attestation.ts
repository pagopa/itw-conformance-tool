import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  issueWalletInstanceAttestationHandler,
  walletInstanceAttestationErrorSchema,
  walletInstanceAttestationRequestSchema,
  walletInstanceAttestationResponseSchema
} from '../handlers/issue-wallet-instance-attestation.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstanceAttestationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instance-attestation',
    method: 'POST',
    schema: {
      operationId: 'issueWalletInstanceAttestation',
      summary: 'Issue a Wallet Instance Attestation',
      description:
        'Validates a signed Wallet Instance Attestation request and returns a provider-signed attestation JWT.',
      tags: ['Wallet Instance Attestation'],
      consumes: ['application/json'],
      produces: ['application/json'],
      body: toFastifyJsonSchema(walletInstanceAttestationRequestSchema),
      response: {
        200: {
          description: 'Provider-signed Wallet Instance Attestation JWT.',
          ...toFastifyJsonSchema(walletInstanceAttestationResponseSchema)
        },
        400: {
          description: 'Malformed or incomplete attestation request.',
          ...toFastifyJsonSchema(walletInstanceAttestationErrorSchema)
        },
        403: {
          description: 'Attestation request rejected by proof-of-possession or integrity checks.',
          ...toFastifyJsonSchema(walletInstanceAttestationErrorSchema)
        }
      }
    },
    handler: issueWalletInstanceAttestationHandler
  });
};

export default walletInstanceAttestationRoute;
