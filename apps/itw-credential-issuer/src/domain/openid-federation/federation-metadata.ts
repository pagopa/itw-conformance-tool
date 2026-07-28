import { convertPemToBase64Der, createTrustMark } from '@itw-conformance-tool/crypto';
import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { signCallback } from '../signer.js';
import { getEntityConfigurationClaimsMetadata } from './entity-configuration-metadata.js';

import type { JwksRepository } from '../signer.js';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const CREDENTIAL_ISSUER_TRUST_MARK_TYPE_SUFFIX = 'trust_marks/issuance/credential_issuer';

/** Builds the fully qualified Credential Issuer Trust Mark type from the configured
 * Trust Anchor entity ID. The Trust Anchor owns this type identifier and must advertise
 * this exact same value in its `trust_mark_issuers` claim
 * (see apps/itw-trust-anchor/src/federation/statements.ts). */
export function getCredentialIssuerTrustMarkType(trustAnchorEntityId: string): string {
  return `${trustAnchorEntityId}/${CREDENTIAL_ISSUER_TRUST_MARK_TYPE_SUFFIX}`;
}

export interface GetFederationMetadataOptions {
  baseURL: string;
  config: IoWalletSdkConfig;
  jwksRepository: JwksRepository;
  trustAnchorEntityId: string;
  /**
   * Overrides the `authority_hints` claim when set (used by the
   * `invalid-trust-anchor` issuer fault). Every other claim, the header, and
   * the signing key are left untouched so the Entity Configuration stays
   * cryptographically valid.
   */
  authorityHintsOverride?: string[];
}

export const getFederationMetadata = async (options: GetFederationMetadataOptions): Promise<string> => {
  const jwk = options.jwksRepository.getSign();

  const signJwtCallback: SignCallback = async ({ toBeSigned }) => signCallback({ jwk: jwk.private, toBeSigned });

  const issuedAt = Math.floor(Date.now() / 1000);
  const credentialIssuerTrustMarkType = getCredentialIssuerTrustMarkType(options.trustAnchorEntityId);
  // Issued by the Trust Anchor about this Credential Issuer and signed with the Trust
  // Anchor's federation key, so a wallet verifies it against the Trust Anchor Entity
  // Configuration it already fetched while building the Trust Chain.
  const credentialIssuerTrustMark = await createTrustMark({
    issuedAt,
    issuerEntityId: options.trustAnchorEntityId,
    signingJwk: options.jwksRepository.getTrustAnchorFederation(),
    subjectEntityId: options.baseURL,
    trustMarkType: credentialIssuerTrustMarkType,
    ttlSeconds: ENTITY_STATEMENT_TTL_SECONDS
  });

  return await createItWalletEntityConfiguration({
    claims: {
      authority_hints: options.authorityHintsOverride ?? [options.trustAnchorEntityId],
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
