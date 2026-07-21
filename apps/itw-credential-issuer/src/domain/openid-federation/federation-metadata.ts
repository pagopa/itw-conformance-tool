import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';
import { importJWK, SignJWT, type JWK } from 'jose';

import { signCallback } from '../signer.js';
import { getEntityConfigurationClaimsMetadata } from './entity-configuration-metadata.js';

import type { JwksRepository } from '../signer.js';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const CREDENTIAL_ISSUER_TRUST_MARK_TYPE_SUFFIX = 'trust_marks/issuance/credential_issuer';

/** Builds the fully qualified Credential Issuer Trust Mark type from the configured
 * Trust Anchor entity ID. The Trust Anchor must advertise this exact same value in its
 * `trust_mark_issuers` claim (see apps/itw-trust-anchor/src/federation/statements.ts). */
export function getCredentialIssuerTrustMarkType(trustAnchorEntityId: string): string {
  return `${trustAnchorEntityId}/${CREDENTIAL_ISSUER_TRUST_MARK_TYPE_SUFFIX}`;
}

async function createCredentialIssuerTrustMark(options: {
  entityId: string;
  issuedAt: number;
  signingJwk: JWK;
  trustMarkType: string;
}): Promise<string> {
  const { entityId, issuedAt, signingJwk, trustMarkType } = options;
  const alg = signingJwk.alg ?? ENTITY_STATEMENT_SIGNING_ALG;
  const key = await importJWK(signingJwk, alg);

  return new SignJWT({
    ref: `${trustMarkType}/compliance`,
    trust_mark_type: trustMarkType
  })
    .setProtectedHeader({ alg, kid: signingJwk.kid, typ: 'trust-mark+jwt' })
    .setIssuedAt(issuedAt)
    .setIssuer(entityId)
    .setSubject(entityId)
    .setExpirationTime(issuedAt + ENTITY_STATEMENT_TTL_SECONDS)
    .sign(key);
}

export interface GetFederationMetadataOptions {
  baseURL: string;
  config: IoWalletSdkConfig;
  jwksRepository: JwksRepository;
  trustAnchorEntityId: string;
}

export const getFederationMetadata = async (options: GetFederationMetadataOptions): Promise<string> => {
  const jwk = options.jwksRepository.getSign();

  const signJwtCallback: SignCallback = async ({ toBeSigned }) => signCallback({ jwk: jwk.private, toBeSigned });

  const issuedAt = Math.floor(Date.now() / 1000);
  const credentialIssuerTrustMarkType = getCredentialIssuerTrustMarkType(options.trustAnchorEntityId);
  const credentialIssuerTrustMark = await createCredentialIssuerTrustMark({
    entityId: options.baseURL,
    issuedAt,
    signingJwk: jwk.private,
    trustMarkType: credentialIssuerTrustMarkType
  });

  return await createItWalletEntityConfiguration({
    claims: {
      authority_hints: [options.trustAnchorEntityId],
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: options.baseURL,
      jwks: {
        keys: [
          {
            ...options.jwksRepository.getSign().public,
            x5c: options.jwksRepository.issuerCertificateChain().map(convertPemToBase64Der)
          }
        ]
      },
      metadata: getEntityConfigurationClaimsMetadata(options.baseURL, options.jwksRepository, options.config),
      sub: options.baseURL,
      trust_marks: [
        {
          trust_mark: credentialIssuerTrustMark,
          trust_mark_type: credentialIssuerTrustMarkType
        }
      ]
    },
    header: { alg: ENTITY_STATEMENT_SIGNING_ALG, kid: jwk.public.kid, typ: 'entity-statement+jwt' },
    signJwtCallback
  });
};
