import { hashCallback, type HashAlgorithm } from '@itw-conformance-tool/crypto';
import { fetchAndValidateTrustChain } from '@pagopa/io-wallet-oid-federation';
import { importJWK, jwtVerify } from 'jose';

import type { VerifyJwtWithJwkCallback } from '@pagopa/io-wallet-oid-federation';
import type { JWK } from 'jose';

type HashCallback = (data: Uint8Array, algorithm: string) => Promise<Uint8Array>;

type LoggerLike = {
  info: (obj: Record<string, unknown>, msg?: string) => void;
  warn: (obj: Record<string, unknown>, msg?: string) => void;
};

export interface FetchTrustChainOptions {
  entityId: string;
  trustAnchorUrl: string;
  timeoutMs?: number;
  logger: LoggerLike;
}

const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

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
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signal = init?.signal == null ? timeoutSignal : AbortSignal.any([init.signal, timeoutSignal]);

    try {
      return await fetch(input, {
        ...init,
        signal
      });
    } catch {
      throw new Error('Trust chain fetch failed');
    }
  };
}

const buildHashCallback = (): HashCallback => async (value, algorithm) =>
  hashCallback(value, algorithm as HashAlgorithm);

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
  if (parsed.pathname === '/') {
    return parsed.origin;
  }
  return parsed.toString();
}

function resolveTrustAnchorEntityId(input: { trustAnchorUrl: string; entityId: string }): string {
  const entityId = toEntityId(input.entityId);
  const resolved = new URL(input.trustAnchorUrl.trim(), entityId).toString();
  return toEntityId(resolved);
}

export async function fetchTrustChain(options: FetchTrustChainOptions): Promise<string[]> {
  const fetchWithTimeout = buildFetchWithTimeout(options);
  const entityId = toEntityId(options.entityId);
  const trustAnchorEntityId = resolveTrustAnchorEntityId({
    trustAnchorUrl: options.trustAnchorUrl,
    entityId
  });

  let trustChain: string[] = [];
  try {
    trustChain = await fetchAndValidateTrustChain(entityId, {
      callbacks: {
        fetch: fetchWithTimeout,
        hash: buildHashCallback(),
        verifyJwt: verifyJwtWithJwk
      },
      trustAnchorUrls: [trustAnchorEntityId]
    });
  } catch {
    return trustChain;
  }

  return trustChain;
}
