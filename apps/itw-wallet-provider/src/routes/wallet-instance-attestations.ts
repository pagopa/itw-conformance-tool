import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  issueWalletInstanceAttestationHandler,
  walletInstanceAttestationErrorSchema,
  walletInstanceAttestationResponseSchema
} from '../handlers/issue-wallet-instance-attestation.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstanceAttestationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instance-attestations',
    method: 'POST',
    schema: {
      operationId: 'createWalletInstanceAttestation',
      summary: 'Issue a Wallet Instance Attestation',
      description:
        'Validates a signed Wallet Instance Attestation request and returns a provider-signed attestation JWT.',
      tags: ['Wallet Instance Attestation'],
      // The request body is the bare compact JWT (text/plain); the JSON envelope
      // `{ assertion }` is accepted too. Both are validated inside the handler,
      // so no body schema is declared here.
      consumes: ['text/plain', 'application/json'],
      produces: ['application/json'],
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
