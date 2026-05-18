import { createHash, randomBytes } from 'node:crypto';

import { compactDecrypt, importJWK, importPKCS8, jwtVerify, type JWK } from 'jose';
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

async function verifyAndExtractKbJwtClaims(
  kbJwt: string,
  sdJwt: string,
  expectedAudience?: string
): Promise<{ nonce: string; sd_hash: string }> {
  const header = JSON.parse(
    Buffer.from(kbJwt.split('.')[0], 'base64').toString('utf8')
  ) as { jwk?: JWK };

  if (!header.jwk) {
    throw new Error('KB-JWT header missing required "jwk" claim');
  }

  const holderPublicKey = await importJWK(header.jwk);

  const payload = await jwtVerify(kbJwt, holderPublicKey, { clockTolerance: 300 });

  const claims = payload.payload as Record<string, unknown>;

  if (typeof claims.nonce !== 'string') {
    throw new Error('KB-JWT missing required "nonce" claim');
  }

  if (typeof claims.sd_hash !== 'string') {
    throw new Error('KB-JWT missing required "sd_hash" claim');
  }

  if (expectedAudience && claims.aud) {
    if (typeof claims.aud === 'string' && claims.aud !== expectedAudience) {
      throw new Error(
        `KB-JWT audience mismatch: expected "${expectedAudience}", got "${claims.aud}"`
      );
    } else if (Array.isArray(claims.aud) && !claims.aud.includes(expectedAudience)) {
      throw new Error(`KB-JWT audience does not include "${expectedAudience}"`);
    }
  }

  // Verify sd_hash matches the SD-JWT disclosure digest
  const disclosures = sdJwt.split('~').slice(1, -1).join('~');
  const expectedSdHash = Buffer.from(
    createHash('sha256').update(disclosures).digest()
  ).toString('base64url');

  if (claims.sd_hash !== expectedSdHash) {
    throw new Error('KB-JWT sd_hash does not match SD-JWT disclosures');
  }

  return {
    nonce: claims.nonce,
    sd_hash: claims.sd_hash
  };
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

        // Verify KB-JWT signatures and extract nonces for each credential
        const verifiedNonces: string[] = [];
        for (const [credentialName, sdJwt] of Object.entries(vpToken)) {
          const parts = sdJwt.split('~');
          const kbJwt = parts[parts.length - 1];

          try {
            const { nonce } = await verifyAndExtractKbJwtClaims(
              kbJwt,
              sdJwt,
              app.rp.clientId
            );
            verifiedNonces.push(nonce);
          } catch (error) {
            throw new Error(
              `KB-JWT verification failed for credential "${credentialName}": ${error instanceof Error ? error.message : String(error)}`
            );
          }
        }

        // Ensure all nonces are consistent
        if (verifiedNonces.length === 0) {
          throw new Error('No key-binding nonce found in presented credentials');
        }
        const firstNonce = verifiedNonces[0];
        if (!verifiedNonces.every((nonce) => nonce === firstNonce)) {
          throw new Error('Nonce mismatch across credentials');
        }

        // Consume the verified nonce
        const consumed = await app.rp.nonceRepository.consume(firstNonce);
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
