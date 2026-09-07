import { createPrivateKey, sign } from 'node:crypto';

import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_4,
  type ItWalletMetadataV1_4,
  type SignCallback
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { generateKeyPair, importJWK, SignJWT, type JWK } from 'jose';

import {
  buildVerifierEntityConfigurationMetadata,
  REDIRECT_URI_PATH,
  REQUEST_URI_PATH,
  RESPONSE_URI_PATH
} from './verifier-metadata.js';

import type { ActiveRpFault } from '../faults/rp-fault-store.js';
import type { PublishedJwk } from './verifier-metadata.js';

/**
 * Builds the Relying Party Entity Configuration — the artifact the wallet reads
 * to discover the Verifier metadata, its keys, its attested endpoints and its
 * position in the federation.
 *
 * It is produced here rather than in the route handler because two callers need
 * the very same bytes: `/.well-known/openid-federation`, which serves it, and
 * the Request Object builder, which inlines it as the first element of a
 * `trust_chain` header. Building it once means an inlined Trust Chain can never
 * describe a Relying Party different from the one the wallet would find by
 * fetching.
 */

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const RELYING_PARTY_TRUST_MARK_PURPOSE = 'presentation';
const RELYING_PARTY_TRUST_MARK_ENTITY_TYPE = 'relying_party';

/**
 * Relying Party fault profiles applied while building the Entity Configuration.
 * The remaining profiles are applied further down the flow, when the Request
 * Object is served, and must leave this artifact nominal.
 */
const ENTITY_CONFIGURATION_FAULT_TYPES = [
  'invalid-trust-anchor',
  'invalid-trust-mark',
  'missing-presentation-trust-mark',
  'unattested-redirect-uri',
  'unattested-request-uri',
  'unattested-response-uri'
] as const;

export type EntityConfigurationFaultType = (typeof ENTITY_CONFIGURATION_FAULT_TYPES)[number];

export function findEntityConfigurationFault(
  fault: ActiveRpFault | undefined
): { fault: ActiveRpFault; type: EntityConfigurationFaultType } | undefined {
  if (!fault) return undefined;

  const type = ENTITY_CONFIGURATION_FAULT_TYPES.find((candidate) => candidate === fault.profile.type);
  return type ? { fault, type } : undefined;
}

/**
 * A syntactically valid, deterministic Entity ID that is never a real
 * federation participant: `.invalid` is reserved by RFC 2606 and guaranteed to
 * never resolve, so it can never accidentally form part of the wallet's
 * expected Trust Chain. Used only by the `invalid-trust-anchor` fault to
 * replace `authority_hints`. Mirrors the Credential Issuer's WP_046a fault.
 */
const INVALID_TRUST_ANCHOR_ENTITY_ID = 'https://wp-079-invalid-trust-anchor.itw-conformance-tool.invalid';

/**
 * Endpoint paths the `unattested-request-uri` (WP_081),
 * `unattested-response-uri` (WP_091a) and `unattested-redirect-uri` (WP_094a)
 * faults publish instead of the live ones.
 *
 * An attested entry is matched against a live URI as a *path prefix*: same
 * origin, and a path that is either equal to the attested path or continues it
 * at a segment boundary (see `isUriUnderAttestedPrefix` in
 * `@itw-conformance-tool/utils`). That is what lets the attested
 * `/auth/request` cover the live `/auth/request/<state>`.
 *
 * Each fault path therefore has to differ from the live one *before* any
 * segment boundary — `-unattested` is appended inside the last segment rather
 * than below it — so a wallet applying that rule cannot accept the URI it is
 * actually handed. No route serves these paths either: nothing ever requests an
 * attested URI, so these values only ever have to fail a comparison.
 * `packages/utils/src/tests/url.test.ts` pins that they do.
 */
const UNATTESTED_REQUEST_URI_PATH = '/auth/request-unattested';
const UNATTESTED_RESPONSE_URI_PATH = '/auth/response-unattested';
const UNATTESTED_REDIRECT_URI_PATH = '/callback-unattested';

/** Private key produced by `generateKeyPair`, kept in memory and never exported. */
type EphemeralSigningKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

function getTrustMarkType(entityId: string): string {
  return `${entityId}/trust_marks/${RELYING_PARTY_TRUST_MARK_PURPOSE}/${RELYING_PARTY_TRUST_MARK_ENTITY_TYPE}`;
}

async function createRelyingPartyTrustMark(options: {
  entityId: string;
  issuedAt: number;
  signingJwk: JWK;
  /**
   * Signs in place of `signingJwk`, whose `kid` and `alg` the Trust Mark still
   * advertises. Used by the `invalid-trust-mark` fault (WP_080) to produce a
   * Trust Mark no federation-published key can verify.
   */
  signingKeyOverride?: EphemeralSigningKey;
  trustMarkType: string;
}): Promise<string> {
  const { entityId, issuedAt, signingJwk, trustMarkType } = options;
  const alg = signingJwk.alg ?? ENTITY_STATEMENT_SIGNING_ALG;
  const key = options.signingKeyOverride ?? (await importJWK(signingJwk, alg));

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

// The SDK builds `toBeSigned` as `base64url(header).base64url(payload)` and appends the
// bytes we return verbatim as the JWT signature, so we must sign `toBeSigned` itself and
// return a raw JWS (IEEE P-1363, R||S) signature. Signing directly with node:crypto avoids
// wrapping `toBeSigned` in a throwaway compact JWS — which would sign a different message
// and yield an entity configuration no verifier can validate. Mirrors the Trust Anchor's
// signer (apps/itw-trust-anchor/src/federation/signer.ts).
const signJwtCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? ENTITY_STATEMENT_SIGNING_ALG;
  const digestAlgorithm =
    alg === 'ES256' ? 'sha256' : alg === 'ES384' ? 'sha384' : alg === 'ES512' ? 'sha512' : undefined;

  if (!digestAlgorithm) {
    throw new Error(`Unsupported federation signing algorithm: ${alg}`);
  }

  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  const signature = sign(digestAlgorithm, Buffer.from(toBeSigned), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });

  return new Uint8Array(signature);
};

export interface BuildRelyingPartyEntityConfigurationOptions {
  /** Relying Party entity identifier, which is also the Entity Configuration `sub`. */
  baseUrl: string;
  encryptionJwk: PublishedJwk;
  /** Entity-Configuration fault to apply, if the active one is applied here at all. */
  faultType?: EntityConfigurationFaultType | undefined;
  federationPrivateJwk: PublishedJwk;
  federationPublicJwk: PublishedJwk;
  signingJwk: PublishedJwk;
  trustAnchorUrl: string;
}

/**
 * Signs the Relying Party Entity Configuration, applying the
 * Entity-Configuration fault the scenario asked for.
 *
 * @returns The signed `entity-statement+jwt`.
 */
export async function buildRelyingPartyEntityConfiguration(
  options: BuildRelyingPartyEntityConfigurationOptions
): Promise<string> {
  const { baseUrl, encryptionJwk, faultType, federationPrivateJwk, federationPublicJwk, signingJwk, trustAnchorUrl } =
    options;
  const issuedAt = Math.floor(Date.now() / 1000);

  // WP_080: the Trust Mark keeps its nominal type, claims and `kid`, but is
  // signed with an ephemeral key that is published nowhere in the federation,
  // so a wallet that verifies Trust Marks cannot validate it.
  const trustMarkSigningKeyOverride =
    faultType === 'invalid-trust-mark' ? (await generateKeyPair(ENTITY_STATEMENT_SIGNING_ALG)).privateKey : undefined;

  const trustMark = await createRelyingPartyTrustMark({
    entityId: baseUrl,
    issuedAt,
    signingJwk: federationPrivateJwk,
    signingKeyOverride: trustMarkSigningKeyOverride,
    trustMarkType: getTrustMarkType(trustAnchorUrl)
  });

  // The attested endpoint lists the wallet must check the engagement
  // `request_uri`, the Request Object `response_uri` and the returned
  // `redirect_uri` against (WP_081, WP_091a, WP_094a). Faults replace one list
  // at a time with a different path, leaving the live endpoints reachable so a
  // wallet that skips the check is observed doing so.
  const metadata: ItWalletMetadataV1_4 = buildVerifierEntityConfigurationMetadata({
    baseUrl,
    encryptionJwk,
    erasure_endpoint: `${baseUrl}/erasure`,
    redirectUris: [
      faultType === 'unattested-redirect-uri'
        ? `${baseUrl}${UNATTESTED_REDIRECT_URI_PATH}`
        : `${baseUrl}${REDIRECT_URI_PATH}`
    ],
    requestUris: [
      faultType === 'unattested-request-uri'
        ? `${baseUrl}${UNATTESTED_REQUEST_URI_PATH}`
        : `${baseUrl}${REQUEST_URI_PATH}`
    ],
    responseUris: [
      faultType === 'unattested-response-uri'
        ? `${baseUrl}${UNATTESTED_RESPONSE_URI_PATH}`
        : `${baseUrl}${RESPONSE_URI_PATH}`
    ],
    signingJwk
  });

  const parsed = itWalletMetadataV1_4.safeParse(metadata);
  if (!parsed.success) {
    throw new ValidationError('Invalid relying party entity configuration metadata', parsed.error);
  }

  return createItWalletEntityConfiguration({
    claims: {
      exp: issuedAt + ENTITY_STATEMENT_TTL_SECONDS,
      iat: issuedAt,
      iss: baseUrl,
      jwks: {
        keys: [federationPublicJwk]
      },
      metadata,
      sub: baseUrl,
      // WP_087: without a Trust Mark the federation does not attest that this
      // Relying Party may request Digital Credential presentations at all.
      trust_marks:
        faultType === 'missing-presentation-trust-mark'
          ? []
          : [
              {
                trust_mark: trustMark,
                trust_mark_type: getTrustMarkType(trustAnchorUrl)
              }
            ],
      // WP_079: an authority hint that can never resolve leaves the wallet
      // unable to build a Trust Chain up to the configured Trust Anchor.
      authority_hints: [faultType === 'invalid-trust-anchor' ? INVALID_TRUST_ANCHOR_ENTITY_ID : trustAnchorUrl]
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: federationPrivateJwk.kid,
      typ: 'entity-statement+jwt'
    },
    signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: federationPrivateJwk, toBeSigned })
  });
}
