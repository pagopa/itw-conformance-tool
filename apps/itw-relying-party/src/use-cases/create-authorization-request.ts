import { createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';

import { createSignJwtCallback } from '@itw-conformance-tool/crypto';
import { createAuthorizationRequest } from '@pagopa/io-wallet-oid4vp';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { extractClientId } from '../crypto/client-id.js';

import type { INonceRepository } from '@itw-conformance-tool/database';
import type { PresentationFlowType, SessionService } from '@itw-conformance-tool/rp';
import type { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

const TTL_MS = 5 * 60 * 1000;
const JAR_SIGNING_ALG = 'ES256';

const CERT_PEM_PATTERN = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

export interface CreateAuthorizationRequestInput {
  baseUrl: string;
  entityId: string;
  dcqlQuery: Record<string, unknown>;
  flowType: PresentationFlowType;
  nonceRepository: INonceRepository;
  rpKeys: {
    authRequestPrivateKeyPem: string;
    authResponsePrivateKeyPem: string;
    signingPrivateKeyPem: string;
    x5cCertPem: string;
  };
  sdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  sessionService: SessionService;
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

async function resolveResponseEncryptionJwk(
  authResponsePrivateKeyPem: string
): Promise<{ [key: string]: unknown; kid: string; kty: string; alg: string; use: string }> {
  const publicJwk = createPublicKey(createPrivateKey(authResponsePrivateKeyPem)).export({ format: 'jwk' }) as JWK;
  const kid = await calculateJwkThumbprint(publicJwk);

  if (typeof publicJwk.kty !== 'string' || publicJwk.kty.length === 0) {
    throw new Error('Auth response public JWK is missing required kty');
  }

  return {
    ...publicJwk,
    alg: 'ECDH-ES',
    kid,
    kty: publicJwk.kty,
    use: 'enc'
  };
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
  const requestObjectClientId = `x509_hash:${clientId}`;
  const responseUri = `${input.baseUrl}/auth/response`;
  const state = randomUUID();
  const nonce = randomBytes(32).toString('hex');
  const requestUri = `${input.baseUrl}/auth/request/${state}`;

  await input.nonceRepository.insert(nonce, Date.now() + TTL_MS);

  const x5c = parseX5cChain(input.rpKeys.x5cCertPem);
  if (x5c.length === 0) {
    throw new Error('x5c certificate chain is empty or not a valid PEM-encoded certificate');
  }

  const encryptionJwk = await resolveResponseEncryptionJwk(input.rpKeys.authResponsePrivateKeyPem);
  const signingKid = await resolveSigningKid(input.rpKeys.signingPrivateKeyPem);
  const signJwt = createSignJwtCallback(input.rpKeys.authRequestPrivateKeyPem, input.rpKeys.signingPrivateKeyPem);

  const authorizationRequestPayload = {
    client_id: requestObjectClientId,
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
    iss: requestObjectClientId,
    nonce,
    request_uri_method: 'get' as const,
    response_mode: 'direct_post.jwt' as const,
    response_type: 'vp_token' as const,
    response_uri: responseUri,
    state
  };

  const result = await createAuthorizationRequest({
    authorizationRequestPayload,
    callbacks: {
      signJwt
    },
    config: input.sdkConfig,
    jar: {
      expiresInSeconds: TTL_MS / 1000,
      jwtSigner: {
        alg: JAR_SIGNING_ALG,
        kid: signingKid,
        method: 'x5c',
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
