import { createHash } from 'node:crypto';

import { fetchAndValidateTrustChain } from '@pagopa/io-wallet-oid-federation';
import { importJWK, jwtVerify } from 'jose';

import type { VerifyJwtWithJwkCallback } from '@pagopa/io-wallet-oid-federation';
import type { JWK } from 'jose';

type HashCallback = (data: Uint8Array, algorithm: string) => Promise<Uint8Array>;

type LoggerLike = {
  info: (obj: Record<string, unknown>, msg?: string) => void;
  error: (obj: Record<string, unknown>, msg?: string) => void;
};

export interface FetchTrustChainOptions {
  entityId: string;
  trustAnchorUrl: string;
  timeoutMs?: number;
  logger: LoggerLike;
}

const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

function normalizeHashAlgorithm(algorithm: string): 'sha256' | 'sha384' | 'sha512' {
  switch (algorithm) {
    case 'sha-256':
      return 'sha256';
    case 'sha-384':
      return 'sha384';
    case 'sha-512':
      return 'sha512';
    default:
      throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
}

const verifyJwtWithJwk: VerifyJwtWithJwkCallback = async (jwtSigner, jwt) => {
  const verificationKey = await importJWK(jwtSigner.publicJwk as JWK, jwtSigner.alg);
  await jwtVerify(jwt.compact, verificationKey, { algorithms: [jwtSigner.alg] });

  return {
    signerJwk: jwtSigner.publicJwk,
    verified: true
  };
};

function buildFetchWithTimeout(options: Pick<FetchTrustChainOptions, 'logger' | 'timeoutMs'>): typeof fetch {
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;

  return async (input, init) => {
    const startedAt = Date.now();
    const method = init?.method ?? 'GET';
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signal = init?.signal == null ? timeoutSignal : AbortSignal.any([init.signal, timeoutSignal]);

    options.logger.info({ method, timeoutMs, url }, 'Fetching trust-chain resource');

    const response = await fetch(input, {
      ...init,
      signal
    });

    options.logger.info(
      {
        durationMs: Date.now() - startedAt,
        method,
        statusCode: response.status,
        url
      },
      'Fetched trust-chain resource'
    );

    return response;
  };
}

function buildHashCallback(): HashCallback {
  return async (value, algorithm) => {
    const hashAlgorithm = normalizeHashAlgorithm(String(algorithm));
    const digest = createHash(hashAlgorithm).update(value).digest();
    return new Uint8Array(digest);
  };
}

function toEntityId(url: string): string {
  const parsed = new URL(url);
  const wellKnownSuffix = '/.well-known/openid-federation';
  if (parsed.pathname !== '/' && parsed.pathname.endsWith('/')) {
    parsed.pathname = parsed.pathname.slice(0, -1);
  }
  if (parsed.pathname.endsWith(wellKnownSuffix)) {
    parsed.pathname = parsed.pathname.slice(0, -wellKnownSuffix.length) || '/';
  }
  if (parsed.pathname !== '/' && parsed.pathname.endsWith('/')) {
    parsed.pathname = parsed.pathname.slice(0, -1);
  }
  return parsed.toString();
}

export async function fetchTrustChain(options: FetchTrustChainOptions): Promise<[string, ...string[]]> {
  const fetchWithTimeout = buildFetchWithTimeout(options);
  const entityId = toEntityId(options.entityId);
  const trustAnchorEntityId = toEntityId(options.trustAnchorUrl);

  try {
    const trustChain = await fetchAndValidateTrustChain(entityId, {
      callbacks: {
        fetch: fetchWithTimeout,
        hash: buildHashCallback(),
        verifyJwt: verifyJwtWithJwk
      },
      trustAnchorUrls: [trustAnchorEntityId]
    });

    if (trustChain.length === 0) {
      throw new Error('Trust chain resolution returned an empty chain');
    }

    options.logger.info(
      {
        entityId,
        trustAnchorEntityId,
        trustAnchorUrl: options.trustAnchorUrl,
        trustChainLength: trustChain.length
      },
      'Trust chain fetched and validated'
    );

    return trustChain as [string, ...string[]];
  } catch (err) {
    options.logger.error(
      {
        entityId,
        err,
        trustAnchorUrl: options.trustAnchorUrl
      },
      'Failed to fetch and validate trust chain'
    );

    throw err;
  }
}
