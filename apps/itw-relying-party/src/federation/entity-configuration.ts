import { Buffer } from 'node:buffer';
import { createPrivateKey, createPublicKey } from 'node:crypto';

import { createItWalletEntityConfiguration, itWalletMetadataV1_3 } from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { PemConverter, X509Certificate } from '@peculiar/x509';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { signJwtCallback } from './signer.js';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { ItWalletEntityConfigurationClaimsOptions, ItWalletMetadataV1_3, JsonWebKey } from '@pagopa/io-wallet-oid-federation';

type EntityConfigurationJwk = ItWalletEntityConfigurationClaimsOptions['jwks']['keys'][number];
type EntityConfigurationJwkSet = ItWalletEntityConfigurationClaimsOptions['jwks'];

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';

function parseCertificateChain(pemChain: string): string[] {
  return PemConverter.decode(pemChain).map((rawCertificate) => {
    const certificate = new X509Certificate(rawCertificate);
    return Buffer.from(certificate.rawData).toString('base64');
  });
}

async function toPublicJwk(privateKeyPem: string, x5c: string[]): Promise<EntityConfigurationJwk> {
  const publicJwk = createPublicKey(createPrivateKey(privateKeyPem)).export({ format: 'jwk' }) as JWK;
  const kid = await calculateJwkThumbprint(publicJwk);

  return {
    ...publicJwk,
    kid,
    kty: String(publicJwk.kty),
    x5c
  };
}

async function toPrivateJwk(privateKeyPem: string, kid: string): Promise<JsonWebKey & Jwk> {
  const privateJwk = createPrivateKey(privateKeyPem).export({ format: 'jwk' });

  return {
    ...privateJwk,
    alg: ENTITY_STATEMENT_SIGNING_ALG,
    kid,
    kty: String(privateJwk.kty)
  };
}

function buildEntityConfigurationMetadata(input: {
  entityId: string;
  requestUri: string;
  responseUri: string;
  verifierJwks: EntityConfigurationJwkSet;
}): ItWalletEntityConfigurationClaimsOptions['metadata'] {
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
      client_id: input.entityId,
      client_name: 'PagoPa S.p.A.',
      encrypted_response_enc_values_supported: ['A256GCM'],
      jwks: input.verifierJwks,
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      request_uris: [input.requestUri],
      response_uris: [input.responseUri],
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

  return parsed.data;
}

export async function createEntityConfigurationJwt(input: {
  entityId: string;
  trustAnchorUrl: string;
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
  federationPrivateKeyPem: string;
  x5cCertPem: string;
}): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const entityId = input.entityId;
  const authorityHint = new URL(input.trustAnchorUrl.trim(), entityId).origin;
  const x5c = parseCertificateChain(input.x5cCertPem);
  const verifierSigningJwk = await toPublicJwk(input.authRequestPrivateKeyPem, x5c);
  const encryptionJwk = await toPublicJwk(input.authResponsePrivateKeyPem, x5c);
  const federationSigningJwk = await toPublicJwk(input.federationPrivateKeyPem, x5c);
  const signingPrivateJwk = await toPrivateJwk(input.federationPrivateKeyPem, String(federationSigningJwk.kid));
  const metadata = buildEntityConfigurationMetadata({
    entityId,
    requestUri: `${entityId}/auth/request`,
    responseUri: `${entityId}/auth/response`,
    verifierJwks: { keys: [verifierSigningJwk, encryptionJwk] }
  });

  return createItWalletEntityConfiguration({
    claims: {
      authority_hints: [authorityHint],
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: entityId,
      jwks: {
        keys: [federationSigningJwk]
      },
      metadata,
      sub: entityId,
      trust_marks: []
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: String(federationSigningJwk.kid),
      typ: 'entity-statement+jwt'
    },
    signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: signingPrivateJwk, toBeSigned })
  });
}
