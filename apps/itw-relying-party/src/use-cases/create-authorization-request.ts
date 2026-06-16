import { createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';

import { createSignJwtCallback } from '@itw-conformance-tool/crypto';
import { createAuthorizationRequest } from '@pagopa/io-wallet-oid4vp';
import { ItWalletSpecsVersion, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { extractClientId } from '../crypto/client-id.js';

import type { EphemeralKeyPair } from '../crypto/ephemeral-keys.js';
import type { INonceRepository } from '@itw-conformance-tool/database';
import type { PresentationFlowType, SessionService } from '@itw-conformance-tool/rp';

const TTL_MS = 5 * 60 * 1000;
const JAR_SIGNING_ALG = 'ES256';
const INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER = 'insecure-http-local-dev';
const SDK_CONFIG = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 });

const CERT_PEM_PATTERN = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

export interface CreateAuthorizationRequestInput {
  baseUrl: string;
  dcqlQuery: Record<string, unknown>;
  ephemeralKeys: EphemeralKeyPair;
  flowType: PresentationFlowType;
  nonceRepository: INonceRepository;
  rpKeys: {
    authRequestPrivateKeyPem: string;
    signingPrivateKeyPem: string;
    x5cCertPem: string;
  };
  sessionService: SessionService;
  trustChain?: [string, ...string[]];
  walletAuthBaseUri: string;
}

export interface CreateAuthorizationRequestResult {
  requestUri: string;
  state: string;
  walletUrl: string;
}

function parseX5cChain(pemChain: string): string[] {
  return Array.from(pemChain.matchAll(CERT_PEM_PATTERN), ([, certificate]) => certificate.replace(/\s+/g, ''));
}

function toSdkJwk(ephemeralKeys: EphemeralKeyPair) {
  if (!ephemeralKeys.publicJwk.kid || !ephemeralKeys.publicJwk.kty) {
    throw new Error('Ephemeral public JWK is missing required kid or kty');
  }

  return {
    ...ephemeralKeys.publicJwk,
    kid: ephemeralKeys.publicJwk.kid,
    kty: ephemeralKeys.publicJwk.kty
  };
}

function resolveTrustChain(trustChain: [string, ...string[]] | undefined): [string, ...string[]] | undefined {
  if (trustChain === undefined || trustChain[0] === INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER) {
    return undefined;
  }

  return trustChain;
}

const SIGNING_KID_CACHE = new Map<string, Promise<string>>();

async function resolveSigningKid(signingPrivateKeyPem: string): Promise<string> {
  const cached = SIGNING_KID_CACHE.get(signingPrivateKeyPem);
  if (cached) {
    return cached;
  }

  const promise = (async () => {
    const publicJwk = createPublicKey(createPrivateKey(signingPrivateKeyPem)).export({ format: 'jwk' }) as JWK;
    return calculateJwkThumbprint(publicJwk);
  })();

  SIGNING_KID_CACHE.set(signingPrivateKeyPem, promise);

  try {
    return await promise;
  } catch (error) {
    SIGNING_KID_CACHE.delete(signingPrivateKeyPem);
    throw error;
  }
}

export async function createAuthorizationRequestUseCase(
  input: CreateAuthorizationRequestInput
): Promise<CreateAuthorizationRequestResult> {
  const clientId = extractClientId(input.baseUrl);
  const responseUri = `${clientId}/auth/response`;
  const state = randomUUID();
  const nonce = randomBytes(32).toString('hex');
  const requestUri = `${clientId}/auth/request/${state}`;

  await input.nonceRepository.insert(nonce, Date.now() + TTL_MS);

  const x5c = parseX5cChain(input.rpKeys.x5cCertPem);
  if (x5c.length === 0) {
    throw new Error('x5c certificate chain is empty or not a valid PEM-encoded certificate');
  }

  const encryptionJwk = toSdkJwk(input.ephemeralKeys);
  const trustChain = resolveTrustChain(input.trustChain);
  const signingKid = await resolveSigningKid(input.rpKeys.signingPrivateKeyPem);
  const signJwt = createSignJwtCallback(input.rpKeys.authRequestPrivateKeyPem, input.rpKeys.signingPrivateKeyPem);

  const result = await createAuthorizationRequest({
    authorizationRequestPayload: {
      client_id: clientId,
      client_metadata: {
        encrypted_response_enc_values_supported: ['A256GCM'],
        jwks: {
          keys: [encryptionJwk]
        },
        vp_formats_supported: {
          'dc+sd-jwt': {
            'kb-jwt_alg_values': ['ES256'],
            'sd-jwt_alg_values': ['ES256']
          }
        }
      },
      dcql_query: input.dcqlQuery,
      iss: clientId,
      nonce,
      request_uri_method: 'get',
      response_mode: 'direct_post.jwt',
      response_type: 'vp_token',
      response_uri: responseUri,
      state
    },
    callbacks: {
      signJwt
    },
    config: SDK_CONFIG,
    jar: {
      expiresInSeconds: TTL_MS / 1000,
      jwtSigner: {
        alg: JAR_SIGNING_ALG,
        kid: signingKid,
        method: 'x5c',
        trustChain,
        x5c
      },
      requestUri
    },
    scheme: input.walletAuthBaseUri
  });

  const walletUrl = new URL(result.authorizationRequest);
  walletUrl.searchParams.set('state', state);

  await input.sessionService.create({
    flowType: input.flowType,
    id: state,
    jwt: result.jar.authorizationRequestJwt,
    ttlMs: TTL_MS
  });

  return {
    requestUri,
    state,
    walletUrl: walletUrl.toString()
  };
}
