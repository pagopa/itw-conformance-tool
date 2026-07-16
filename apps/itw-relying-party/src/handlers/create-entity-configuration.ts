import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_3,
  type ItWalletMetadataV1_3,
  type SignCallback
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { CompactSign, importJWK } from 'jose';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';

export const entityConfigurationResponseSchema = z.string().describe('Signed OpenID Federation entity statement JWT.');

const signJwtCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? 'ES256';
  const key = await importJWK(jwk, alg);
  const jws = await new CompactSign(toBeSigned).setProtectedHeader({ alg }).sign(key);

  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new Error('JWS compact format is not valid');
  }

  const signatureBase64Url = parts[2];
  const signatureBase64 = Buffer.from(signatureBase64Url, 'base64url').toString('base64');
  return new Uint8Array(Buffer.from(signatureBase64, 'base64'));
};

export const createEntityConfigurationHandler = async (
  req: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { BASE_URL } = req.server.config;
  const federationPublicKey = req.server.jwks.federation.public;
  const federationPrivateJwk = req.server.jwks.federation.private;
  const signingPublicKey = req.server.jwks.sig.public;
  const encryptionPublicKey = req.server.jwks.enc.public;
  const issuedAt = Math.floor(Date.now() / 1000);

  const metadata = {
    federation_entity: {
      contacts: ['info@pagopa.it'],
      homepage_uri: 'https://io.italia.it',
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      organization_name: 'PagoPa S.p.A.',
      policy_uri: 'https://io.italia.it/privacy-policy'
    },
    openid_credential_verifier: {
      application_type: 'web',
      client_id: BASE_URL,
      client_name: 'PagoPa S.p.A.',
      encrypted_response_enc_values_supported: ['A256GCM'],
      jwks: {
        keys: [signingPublicKey, encryptionPublicKey]
      },
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      request_uris: [`${BASE_URL}/auth/request`],
      response_uris: [`${BASE_URL}/auth/response`],
      vp_formats_supported: {
        'dc+sd-jwt': {
          'kb-jwt_alg_values': ['ES256'],
          'sd-jwt_alg_values': ['ES256']
        }
      }
    }
  } satisfies ItWalletMetadataV1_3;

  const parsed = itWalletMetadataV1_3.safeParse(metadata);
  if (!parsed.success) {
    throw new ValidationError('Invalid relying party entity configuration metadata', parsed.error);
  }

  const jwt = await createItWalletEntityConfiguration({
    claims: {
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: BASE_URL,
      jwks: {
        keys: [federationPublicKey]
      },
      metadata,
      sub: BASE_URL,
      trust_marks: []
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: federationPrivateJwk.kid,
      typ: 'entity-statement+jwt'
    },
    signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: federationPrivateJwk, toBeSigned })
  });

  return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(jwt);
};
