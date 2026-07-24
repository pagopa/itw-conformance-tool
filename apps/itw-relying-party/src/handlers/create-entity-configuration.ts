import { createPrivateKey, sign } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_3,
  type ItWalletMetadataV1_3,
  type SignCallback
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import { importJWK, SignJWT, type JWK } from 'jose';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
const ENTITY_STATEMENT_SIGNING_ALG = 'ES256';
const RELYING_PARTY_TRUST_MARK_PURPOSE = 'presentation';
const RELYING_PARTY_TRUST_MARK_ENTITY_TYPE = 'relying_party';

function getTrustMarkType(entityId: string): string {
  return `${entityId}/trust_marks/${RELYING_PARTY_TRUST_MARK_PURPOSE}/${RELYING_PARTY_TRUST_MARK_ENTITY_TYPE}`;
}

async function createRelyingPartyTrustMark(options: {
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
      scenarioId: req.conformance?.correlation?.scenarioId ?? null,
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

  const trustMark = await createRelyingPartyTrustMark({
    entityId: BASE_URL,
    issuedAt,
    signingJwk: federationPrivateJwk,
    trustMarkType: getTrustMarkType(TRUST_ANCHOR_URL)
  });

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
      trust_marks: [
        {
          trust_mark: trustMark,
          trust_mark_type: getTrustMarkType(TRUST_ANCHOR_URL)
        }
      ],
      authority_hints: [TRUST_ANCHOR_URL]
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
