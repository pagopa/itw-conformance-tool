import { createItWalletEntityConfiguration, itWalletMetadataV1_3 } from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { signJwtCallback } from './signer.js';

import type { JwkKey } from '../plugins/keys.js';
import type {
  ItWalletEntityConfigurationClaimsOptions,
  ItWalletMetadataV1_3,
  JsonWebKey
} from '@pagopa/io-wallet-oid-federation';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';
const RELYING_PARTY_TRUST_MARK_TYPE = 'trust_marks/presentation/relying_party';
const CREDENTIAL_ISSUER_TRUST_MARK_TYPE = 'trust_marks/issuance/credential_issuer';

/** Identifies which leaf entity a subordinate statement is being produced for, so the
 * correct public-JWK derivation (see {@link toRpPublicJwk}) can be selected. */
export type SubordinateEntityKind = 'issuer' | 'rp';

/** Strips private key material from a stored federation JWK, preserving every other
 * member (including `kid`) unchanged.
 *
 * This matches the issuer's own derivation (packages/issuer/src/crypto.ts `toPublicJwk`)
 * and is also correct for the Trust Anchor's own key: neither the issuer nor the Trust
 * Anchor ever recompute their `kid`, so the stored `kid` is exactly what each entity
 * advertises in its own entity configuration.
 */
function stripPrivateParams(jwk: JwkKey): JsonWebKey {
  const { d, key_ops, ...publicJwk } = jwk;
  void d;
  void key_ops;

  if (typeof publicJwk.kty !== 'string' || publicJwk.kty.length === 0) {
    throw new Error('Federation JWK is missing a valid "kty"');
  }
  if (typeof publicJwk.kid !== 'string' || publicJwk.kid.length === 0) {
    throw new Error('Federation JWK is missing a valid "kid"');
  }

  return publicJwk as JsonWebKey;
}

/** Derives the relying party's public federation JWK the same way the RP derives it for
 * itself (apps/itw-relying-party/src/federation/entity-configuration.ts `toPublicJwk`):
 * the stored `kid` is discarded and replaced with an RFC 7638 JWK thumbprint computed
 * over the key.
 *
 * The RP computes this thumbprint from a PEM round-trip of its private key; computing
 * `calculateJwkThumbprint` directly against the stored private JWK yields an identical
 * result because RFC 7638 thumbprints only cover a key's canonical required members
 * (e.g. `kty`, `crv`, `x`, `y` for EC) and ignore any other members present, such as `d`
 * or the original `kid`. Replicating the RP's exact `kid` here is required so that the
 * subordinate statement's JWK matches what the RP itself advertises (see
 * `@pagopa/io-wallet-oid-federation`'s trust-chain validation, which looks up the leaf's
 * signing key by `kid` inside the superior's subordinate statement).
 */
async function toRpPublicJwk(jwk: JwkKey): Promise<JsonWebKey> {
  const { d, key_ops, kid: _storedKid, ...publicJwk } = jwk;
  void d;
  void key_ops;
  void _storedKid;

  if (typeof publicJwk.kty !== 'string' || publicJwk.kty.length === 0) {
    throw new Error('Federation JWK is missing a valid "kty"');
  }

  const kid = await calculateJwkThumbprint(jwk as unknown as JWK);

  return { ...publicJwk, kid } as JsonWebKey;
}

/** Merges a resolved, non-empty `kid`/`kty` back onto the full stored private JWK
 * (private key material included) so it satisfies the SDK's `SignCallback` input type,
 * which requires both fields as non-optional strings. The stored `JwkKey` type keeps them
 * optional since not every persisted key is guaranteed populated; the caller is
 * responsible for resolving and validating both beforehand (see {@link stripPrivateParams}
 * and {@link toRpPublicJwk}).
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
  federationPrivateJwk: JwkKey;
  issuerEntityId: string;
  relyingPartyEntityId: string;
  trustAnchorBaseUrl: string;
}): Promise<string> {
  const { federationPrivateJwk, issuerEntityId, relyingPartyEntityId, trustAnchorBaseUrl } = options;
  const publicJwk = stripPrivateParams(federationPrivateJwk);
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
      jwks: { keys: [publicJwk] },
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

/** Builds a Trust Anchor-signed subordinate statement about a leaf entity (the issuer or
 * the RP), for use behind `GET /fetch?sub=<entity-id>`.
 */
export async function createSubordinate(options: {
  federationPrivateJwk: JwkKey;
  subjectEntityId: string;
  subjectKind: SubordinateEntityKind;
  subjectPrivateJwk: JwkKey;
  trustAnchorBaseUrl: string;
}): Promise<string> {
  const { federationPrivateJwk, subjectEntityId, subjectKind, subjectPrivateJwk, trustAnchorBaseUrl } = options;

  const trustAnchorPublicJwk = stripPrivateParams(federationPrivateJwk);
  const subjectPublicJwk =
    subjectKind === 'rp' ? await toRpPublicJwk(subjectPrivateJwk) : stripPrivateParams(subjectPrivateJwk);

  // The subject's federation public key must be present so a verifier can validate the
  // entity configuration the subject signs for itself. The Trust Anchor's own signing key
  // must ALSO be resolvable from this same array by `header.kid` (required internally by
  // `createItWalletEntityConfiguration`), so it is appended whenever it doesn't already
  // share the subject's `kid`.
  const keys = [subjectPublicJwk];
  if (trustAnchorPublicJwk.kid !== subjectPublicJwk.kid) {
    keys.push(trustAnchorPublicJwk);
  }

  const issuedAt = Math.floor(Date.now() / 1000);

  return createItWalletEntityConfiguration({
    claims: {
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: trustAnchorBaseUrl,
      jwks: { keys },
      sub: subjectEntityId
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
