import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  createKeyAttestationHandler,
  keyAttestationErrorSchema,
  keyAttestationResponseSchema
} from '../handlers/create-key-attestation.js';

import type { FastifyPluginAsync } from 'fastify';

const keyAttestationsRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/key-attestations',
    method: 'POST',
    schema: {
      operationId: 'createKeyAttestation',
      summary: 'Issue a Key Attestation',
      description:
        'Validates a signed Key Attestation request and returns a provider-signed Key Attestation JWT for the requested keys.',
      tags: ['Key Attestation'],
      // Body is the bare compact JWT (text/plain); validated inside the handler.
      consumes: ['text/plain', 'application/json'],
      produces: ['application/json'],
      response: {
        200: {
          description: 'Provider-signed Key Attestation JWT.',
          ...toFastifyJsonSchema(keyAttestationResponseSchema)
        },
        400: {
          description: 'Malformed or incomplete Key Attestation request.',
          ...toFastifyJsonSchema(keyAttestationErrorSchema)
        },
        403: {
          description: 'Key Attestation request rejected by proof-of-possession or integrity checks.',
          ...toFastifyJsonSchema(keyAttestationErrorSchema)
        }
      }
    },
    handler: createKeyAttestationHandler
  });
};

export default keyAttestationsRoute;
