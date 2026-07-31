import { createPrivateKey, sign } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_4,
  type ItWalletMetadataV1_4,
  type SignCallback
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { generateKeyPair, importJWK, SignJWT, type JWK } from 'jose';
import z from 'zod';

import {
  buildVerifierEntityConfigurationMetadata,
  REDIRECT_URI_PATH,
  REQUEST_URI_PATH,
  RESPONSE_URI_PATH
} from '../domain/verifier-metadata.js';
import { emitRpFaultApplied } from '../faults/rp-fault-evidence.js';

import type { ActiveRpFault } from '../faults/rp-fault-store.js';
import type { FastifyReply, FastifyRequest } from 'fastify';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const RELYING_PARTY_TRUST_MARK_PURPOSE = 'presentation';
const RELYING_PARTY_TRUST_MARK_ENTITY_TYPE = 'relying_party';

/**
 * Relying Party fault profiles applied while building the Entity Configuration.
 * The remaining profiles are applied further down the flow, when the Request
 * Object is served, and must leave this handler's output nominal.
 */
const ENTITY_CONFIGURATION_FAULT_TYPES = [
  'invalid-trust-anchor',
  'invalid-trust-mark',
  'missing-presentation-trust-mark',
  'unattested-redirect-uri',
  'unattested-request-uri',
  'unattested-response-uri'
] as const;

type EntityConfigurationFaultType = (typeof ENTITY_CONFIGURATION_FAULT_TYPES)[number];

function findEntityConfigurationFault(
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

export const entityConfigurationResponseSchema = z.string().describe('Signed OpenID Federation entity statement JWT.');

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

export const createEntityConfigurationHandler = async (
  req: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> => {
  // The wallet fetches the RP Entity Configuration to discover its metadata and
  // verifier keys (WP_078 / WP_084). The request carries no scenario
  // correlation, so it is adopted as uncorrelated evidence narrowed by the
  // endpoint diagnostic.
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.metadata.requested',
      correlationId: req.conformance?.correlation?.correlationId ?? null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/.well-known/openid-federation' }
    })
  );

  const { BASE_URL, TRUST_ANCHOR_URL } = req.server.config;
  const federationPublicKey = req.server.jwks.federation.public;
  const federationPrivateJwk = req.server.jwks.federation.private;
  const signingPublicKey = req.server.jwks.sig.public;
  const encryptionPublicKey = req.server.jwks.enc.public;
  const issuedAt = Math.floor(Date.now() / 1000);

  const activeFault = findEntityConfigurationFault(req.server.rpFaultStore.getActive());

  // WP_080: the Trust Mark keeps its nominal type, claims and `kid`, but is
  // signed with an ephemeral key that is published nowhere in the federation,
  // so a wallet that verifies Trust Marks cannot validate it.
  const trustMarkSigningKeyOverride =
    activeFault?.type === 'invalid-trust-mark'
      ? (await generateKeyPair(ENTITY_STATEMENT_SIGNING_ALG)).privateKey
      : undefined;

  const trustMark = await createRelyingPartyTrustMark({
    entityId: BASE_URL,
    issuedAt,
    signingJwk: federationPrivateJwk,
    signingKeyOverride: trustMarkSigningKeyOverride,
    trustMarkType: getTrustMarkType(TRUST_ANCHOR_URL)
  });

  // The attested endpoint lists the wallet must check the engagement
  // `request_uri`, the Request Object `response_uri` and the returned
  // `redirect_uri` against (WP_081, WP_091a, WP_094a). Faults replace one list
  // at a time with a different path, leaving the live endpoints reachable so a
  // wallet that skips the check is observed doing so.
  const metadata: ItWalletMetadataV1_4 = buildVerifierEntityConfigurationMetadata({
    baseUrl: BASE_URL,
    encryptionJwk: encryptionPublicKey,
    erasure_endpoint: `${BASE_URL}/erasure`,
    redirectUris: [
      activeFault?.type === 'unattested-redirect-uri'
        ? `${BASE_URL}${UNATTESTED_REDIRECT_URI_PATH}`
        : `${BASE_URL}${REDIRECT_URI_PATH}`
    ],
    requestUris: [
      activeFault?.type === 'unattested-request-uri'
        ? `${BASE_URL}${UNATTESTED_REQUEST_URI_PATH}`
        : `${BASE_URL}${REQUEST_URI_PATH}`
    ],
    responseUris: [
      activeFault?.type === 'unattested-response-uri'
        ? `${BASE_URL}${UNATTESTED_RESPONSE_URI_PATH}`
        : `${BASE_URL}${RESPONSE_URI_PATH}`
    ],
    signingJwk: signingPublicKey
  });

  const parsed = itWalletMetadataV1_4.safeParse(metadata);
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
      // WP_087: without a Trust Mark the federation does not attest that this
      // Relying Party may request Digital Credential presentations at all.
      trust_marks:
        activeFault?.type === 'missing-presentation-trust-mark'
          ? []
          : [
              {
                trust_mark: trustMark,
                trust_mark_type: getTrustMarkType(TRUST_ANCHOR_URL)
              }
            ],
      // WP_079: an authority hint that can never resolve leaves the wallet
      // unable to build a Trust Chain up to the configured Trust Anchor.
      authority_hints: [
        activeFault?.type === 'invalid-trust-anchor' ? INVALID_TRUST_ANCHOR_ENTITY_ID : TRUST_ANCHOR_URL
      ]
    },
    header: {
      alg: ENTITY_STATEMENT_SIGNING_ALG,
      kid: federationPrivateJwk.kid,
      typ: 'entity-statement+jwt'
    },
    signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: federationPrivateJwk, toBeSigned })
  });

  if (activeFault) {
    // Emission failures must not be reported as a successfully applied fault:
    // any error here propagates instead of emitting a false "applied" event.
    await emitRpFaultApplied(req, {
      artifact: jwt,
      endpoint: '/.well-known/openid-federation',
      fault: activeFault.fault
    });
  }

  return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(jwt);
};
