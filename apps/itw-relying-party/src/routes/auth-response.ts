import { randomBytes } from 'node:crypto';

import { compactDecrypt, importPKCS8 } from 'jose';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

import type { PresentationValues } from '@itw-conformance-tool/rp';
import type { FastifyPluginAsync } from 'fastify';

const responseBodySchema = z
  .object({
    error: z
      .enum([
        'invalid_request_object',
        'invalid_request_uri',
        'vp_formats_not_supported',
        'invalid_request',
        'access_denied',
        'invalid_client'
      ])
      .optional(),
    error_description: z.string().optional(),
    response: z.string().optional(),
    state: z.string().optional()
  })
  .refine((data) => data.response !== undefined || (data.error && data.state), {
    message: "Either 'response' or 'error, state' must be present"
  });

const decryptedAuthorizationResponseSchema = z.object({
  state: z.string(),
  vp_token: z.record(z.string(), z.string())
});

function decodeDisclosureValues(vpToken: Record<string, string>): PresentationValues {
  const values: PresentationValues = [];

  for (const sdJwt of Object.values(vpToken)) {
    const disclosures = sdJwt.split('~').slice(1, -1);
    const parsedClaims: Record<string, string | null> = {};
    for (const disclosure of disclosures) {
      try {
        const decoded = JSON.parse(Buffer.from(disclosure, 'base64').toString('utf8')) as unknown;
        if (Array.isArray(decoded) && decoded.length >= 3 && typeof decoded[1] === 'string') {
          parsedClaims[decoded[1]] = decoded[2] === null || decoded[2] === undefined ? null : String(decoded[2]);
        }
      } catch {
        // Ignore malformed disclosure entries.
      }
    }
    if (Object.keys(parsedClaims).length > 0) {
      values.push(parsedClaims);
    }
  }

  return values;
}

function extractLocalNonces(vpToken: Record<string, string>): string[] {
  const localNonces: string[] = [];

  for (const sdJwt of Object.values(vpToken)) {
    const parts = sdJwt.split('~');
    const kbJwt = parts[parts.length - 1];
    const decodedKbJwt = jwt.decode(kbJwt);
    if (decodedKbJwt && typeof decodedKbJwt !== 'string' && typeof decodedKbJwt.nonce === 'string') {
      localNonces.push(decodedKbJwt.nonce);
    }
  }

  return localNonces;
}

function assertNonceConsistency(localNonces: string[]): string | undefined {
  if (localNonces.length === 0) {
    return undefined;
  }
  const firstNonce = localNonces[0];
  const allEqual = localNonces.every((nonce) => nonce === firstNonce);
  if (!allEqual) {
    throw new Error('Nonce mismatch across credentials');
  }
  return firstNonce;
}

async function decryptAuthorizationResponse(
  response: string,
  keyPem: string
): Promise<z.infer<typeof decryptedAuthorizationResponseSchema>> {
  const privateKey = await importPKCS8(keyPem, 'ECDH-ES');
  const { plaintext } = await compactDecrypt(response, privateKey);
  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
  return decryptedAuthorizationResponseSchema.parse(payload);
}

const authResponseRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/auth/response',
    method: 'POST',
    schema: {
      tags: ['Relying Party']
    },
    handler: async (request, reply) => {
      const parsedBody = responseBodySchema.safeParse(request.body);
      if (!parsedBody.success) {
        return reply.code(400).send({ message: 'The request is missing required parameters' });
      }

      if (parsedBody.data.response === undefined) {
        if (parsedBody.data.state === undefined) {
          return reply.code(400).send({ message: 'The request is missing required parameters' });
        }
        await app.rp.sessionService.update(parsedBody.data.state, 'rejected');
        return reply.code(200).send({});
      }

      let state: string | undefined;
      try {
        const { state: parsedState, vp_token: vpToken } = await decryptAuthorizationResponse(
          parsedBody.data.response,
          app.rp.authResponsePrivateKeyPem
        );
        state = parsedState;

        const localNonces = extractLocalNonces(vpToken);
        const localNonce = assertNonceConsistency(localNonces);
        if (localNonce === undefined) {
          throw new Error('The authorization response is missing the nonce provided in the request object');
        }

        const consumed = await app.rp.nonceRepository.consume(localNonce);
        if (!consumed) {
          throw new Error('The nonce does not match with the one provided in the request object');
        }

        const values = decodeDisclosureValues(vpToken);
        const responseCode = randomBytes(32).toString('hex');
        const redirectUri = `${app.rp.basePath}/success.html?response_code=${responseCode}`;

        await app.rp.sessionService.update(state, 'verified', {
          redirectUri,
          values
        });

        return reply.code(200).send({ redirect_uri: redirectUri });
      } catch (error) {
        if (state !== undefined) {
          await app.rp.sessionService.update(state, 'denied');
        }
        throw error;
      }
    }
  });
};

export default authResponseRoute;
