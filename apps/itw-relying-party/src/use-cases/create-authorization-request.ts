import { createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';

import { createSignJwtCallback } from '@itw-conformance-tool/crypto';
import { createAuthorizationRequest } from '@pagopa/io-wallet-oid4vp';
import { ItWalletSpecsVersion, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, type JWK } from 'jose';

import { extractClientId } from '../crypto/client-id.js';

import type { INonceRepository } from '@itw-conformance-tool/database';
import type { PresentationFlowType, SessionService } from '@itw-conformance-tool/rp';

const TTL_MS = 5 * 60 * 1000;
const JAR_SIGNING_ALG = 'ES256';
const INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER = 'insecure-http-local-dev';
const SDK_CONFIG_V1_0 = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
const SDK_CONFIG_X5C = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });

const CERT_PEM_PATTERN = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
const LOCAL_DEV_TRUST_CHAIN_JWT_PATTERN = /^eyJ/; // Looks like a JWT (starts with 'eyJ' in base64)

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
  const clientId = extractClientId(input.entityId);
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

  const hasRealTrustChain =
    input.trustChain !== undefined &&
    input.trustChain.length > 0 &&
    input.trustChain[0] !== INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER &&
    // Accept any JWT-looking token (starts with 'eyJ')
    // This includes both real federation chain and signed local-dev JWTs
    LOCAL_DEV_TRUST_CHAIN_JWT_PATTERN.test(input.trustChain[0]);

  const requestObjectClientId = hasRealTrustChain ? clientId : `x509_hash:${clientId}`;
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

  const result = hasRealTrustChain
    ? await createAuthorizationRequest({
        authorizationRequestPayload,
        callbacks: {
          signJwt
        },
        config: SDK_CONFIG_V1_0,
        jar: {
          expiresInSeconds: TTL_MS / 1000,
          jwtSigner: {
            alg: JAR_SIGNING_ALG,
            kid: signingKid,
            method: 'federation',
            trustChain: input.trustChain as [string, ...string[]]
          },
          requestUri
        },
        scheme: input.walletAuthBaseUri
      })
    : await createAuthorizationRequest({
        authorizationRequestPayload,
        callbacks: {
          signJwt
        },
        config: SDK_CONFIG_X5C,
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
