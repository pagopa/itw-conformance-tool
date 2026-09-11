import { createItWalletEntityConfiguration, itWalletMetadataV1_3 } from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';

import { assertPublishableJwk, stripPrivateParams, withCertificateChain } from './public-jwk.js';
import { signJwtCallback } from './signer.js';

import type { JwkKey } from '../plugins/keys.js';
import type {
  ItWalletEntityConfigurationClaimsOptions,
  ItWalletMetadataV1_3,
  JsonWebKey,
  MetadataPolicyOperator
} from '@pagopa/io-wallet-oid-federation';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';
const RELYING_PARTY_TRUST_MARK_TYPE = 'trust_marks/presentation/relying_party';
const CREDENTIAL_ISSUER_TRUST_MARK_TYPE = 'trust_marks/issuance/credential_issuer';

/** Merges a resolved, non-empty `kid`/`kty` back onto the full stored private JWK
 * (private key material included) so it satisfies the SDK's `SignCallback` input type,
 * which requires both fields as non-optional strings. The stored `JwkKey` type keeps them
 * optional since not every persisted key is guaranteed populated; the caller is
 * responsible for resolving and validating both beforehand (see {@link stripPrivateParams}).
 */
function toSigningJwk(privateJwk: JwkKey, publicJwk: JsonWebKey): JsonWebKey {
  return { ...privateJwk, kid: publicJwk.kid, kty: publicJwk.kty } as JsonWebKey;
}

/** Builds the Trust Anchor's own self-signed entity configuration.
 *
 * The statement advertises the Trust Anchor's `/fetch` endpoint and its own federation
 * public key, and contains no `authority_hints` since the Trust Anchor is the root of the
 * local trust chain.
 */
export async function createTrustAnchorEntityConfiguration(options: {
  /**
   * The DER-encoded self-signed certificate for `federationPrivateJwk`,
   * published as the key's `x5c`. Omitted when the key being published is not
   * the one the certificate certifies — the
   * `entity-configuration-nonmatching-signing-key` fault substitutes another —
   * since a certificate that does not match the key it accompanies would be a
   * second, unasked-for defect on top of the one the scenario is exercising.
   */
  federationCertificateChain?: string[];
  federationPrivateJwk: JwkKey;
  issuerEntityId: string;
  relyingPartyEntityId: string;
  trustAnchorBaseUrl: string;
}): Promise<string> {
  const { federationCertificateChain, federationPrivateJwk, issuerEntityId, relyingPartyEntityId, trustAnchorBaseUrl } =
    options;
  const publicJwk = stripPrivateParams(federationPrivateJwk);
  const publishedJwk = withCertificateChain(publicJwk, federationCertificateChain);
  const issuedAt = Math.floor(Date.now() / 1000);

  const metadata: ItWalletMetadataV1_3 = {
    federation_entity: {
      contacts: ['info@pagopa.it'],
      federation_fetch_endpoint: `${trustAnchorBaseUrl}/fetch`,
      homepage_uri: 'https://io.italia.it',
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      organization_name: 'PagoPa S.p.A.',
      policy_uri: 'https://io.italia.it/privacy-policy'
    }
  };

  const parsedMetadata = itWalletMetadataV1_3.safeParse(metadata);
  if (!parsedMetadata.success) {
    throw new ValidationError('Invalid Trust Anchor entity configuration metadata', parsedMetadata.error);
  }

  return createItWalletEntityConfiguration({
    claims: {
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: trustAnchorBaseUrl,
      jwks: { keys: [publishedJwk] },
      metadata: parsedMetadata.data as ItWalletEntityConfigurationClaimsOptions['metadata'],
      sub: trustAnchorBaseUrl,
      trust_mark_issuers: {
        [`${trustAnchorBaseUrl}/${CREDENTIAL_ISSUER_TRUST_MARK_TYPE}`]: [issuerEntityId],
        [`${trustAnchorBaseUrl}/${RELYING_PARTY_TRUST_MARK_TYPE}`]: [relyingPartyEntityId]
      }
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: publicJwk.kid,
      typ: ENTITY_STATEMENT_TYP
    },
    signJwtCallback: async ({ toBeSigned }) =>
      signJwtCallback({ jwk: toSigningJwk(federationPrivateJwk, publicJwk), toBeSigned })
  });
}

/** Builds a Trust Anchor-signed subordinate statement about a leaf entity (the issuer,
 * the RP or the Wallet Provider), for use behind `GET /fetch?sub=<entity-id>`.
 */
export async function createSubordinate(options: {
  /**
   * The Trust Anchor's own self-signed certificate, DER-encoded, published as
   * the `x5c` of the Trust Anchor key below. Optional so a caller holding no
   * certificate still produces a valid statement, just without the binding.
   */
  federationCertificateChain?: string[];
  federationPrivateJwk: JwkKey;
  subjectEntityId: string;
  /**
   * The subject's federation key exactly as it is to be published: `kid` already
   * resolved the way the subject itself advertises it, and the certifying `x5c`
   * already attached. The `keys` plugin derives it once at startup — see
   * `TrustAnchorKeys` — so this builder never sees the subject's private key
   * material, which it has no use for.
   */
  subjectPublicJwk: JsonWebKey;
  trustAnchorBaseUrl: string;
  metadataPolicy?: Record<string, Record<string, MetadataPolicyOperator>> | undefined;
}): Promise<string> {
  const {
    federationCertificateChain,
    federationPrivateJwk,
    subjectEntityId,
    subjectPublicJwk,
    trustAnchorBaseUrl,
    metadataPolicy
  } = options;

  assertPublishableJwk(subjectPublicJwk);
  const trustAnchorPublicJwk = stripPrivateParams(federationPrivateJwk);

  // The subject's federation public key must be present so a verifier can validate the
  // entity configuration the subject signs for itself. The Trust Anchor's own signing key
  // must ALSO be resolvable from this same array by `header.kid` (required internally by
  // `createItWalletEntityConfiguration`), so it is appended whenever it doesn't already
  // share the subject's `kid`.
  //
  // Each carries the chain certifying it, so the statement answers "which key"
  // and "certified by whom" in one artifact: a wallet resolving a Trust Chain
  // reads the subject's chain here without fetching the subject's own Entity
  // Configuration, and reads the certificate for the key that signed this
  // statement without fetching the Trust Anchor's. The Trust Anchor's chain is
  // attached here rather than at load time because a fault publishes this key
  // without one.
  const keys = [subjectPublicJwk];
  if (trustAnchorPublicJwk.kid !== subjectPublicJwk.kid) {
    keys.push(withCertificateChain(trustAnchorPublicJwk, federationCertificateChain));
  }

  const issuedAt = Math.floor(Date.now() / 1000);

  return createItWalletEntityConfiguration({
    claims: {
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: trustAnchorBaseUrl,
      jwks: { keys },
      sub: subjectEntityId,
      metadata_policy: metadataPolicy
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: trustAnchorPublicJwk.kid,
      typ: ENTITY_STATEMENT_TYP
    },
    signJwtCallback: async ({ toBeSigned }) =>
      signJwtCallback({ jwk: toSigningJwk(federationPrivateJwk, trustAnchorPublicJwk), toBeSigned })
  });
}
