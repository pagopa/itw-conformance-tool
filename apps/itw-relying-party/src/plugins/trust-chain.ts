import fp from 'fastify-plugin';

import { createEntityConfigurationJwt } from '../federation/entity-configuration.js';
import { fetchTrustChain } from '../trust-chain/fetch-trust-chain.js';

declare module 'fastify' {
  interface FastifyInstance {
    trustChain: string[];
    trustChainSource: 'real' | 'local-dev';
  }
}

const DEFAULT_TRUST_CHAIN_FETCH_TIMEOUT_MS = 10_000;
const DEFAULT_TRUST_CHAIN_FETCH_RETRIES = 3;
const DEFAULT_TRUST_CHAIN_RETRY_DELAY_MS = 300;
const INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER = 'insecure-http-local-dev';

function isHttpUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'http:';
  } catch {
    return false;
  }
}

function resolveFetchTimeoutMs(value: string | undefined): number {
  if (value === undefined || value.trim().length === 0) {
    return DEFAULT_TRUST_CHAIN_FETCH_TIMEOUT_MS;
  }

  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 1) {
    return DEFAULT_TRUST_CHAIN_FETCH_TIMEOUT_MS;
  }

  return parsed;
}

function resolvePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 1) {
    return fallback;
  }

  return parsed;
}

function waitMs(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

async function generateLocalDevTrustChainJwt(input: {
  entityId: string;
  trustAnchorUrl?: string;
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
  federationPrivateKeyPem: string;
  x5cCertPem: string;
}): Promise<string> {
  // For local development, use the actual entity statement as trust chain JWT
  // This contains the RP's JWKS and can be verified by WCT
  return createEntityConfigurationJwt(input);
}

export default fp(
  async function trustChainPlugin(app) {
    const { entityId, trustAnchorUrl } = app.config;
    if (trustAnchorUrl === undefined || trustAnchorUrl.trim().length === 0) {
      app.decorate('trustChain', [INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER]);
      app.decorate('trustChainSource', 'local-dev');
      return;
    }

    const timeoutMs = resolveFetchTimeoutMs(process.env.ITW_CT_TRUST_CHAIN_FETCH_TIMEOUT_MS);
    const maxRetries = resolvePositiveInt(
      process.env.ITW_CT_TRUST_CHAIN_FETCH_RETRIES,
      DEFAULT_TRUST_CHAIN_FETCH_RETRIES
    );
    const retryDelayMs = resolvePositiveInt(
      process.env.ITW_CT_TRUST_CHAIN_FETCH_RETRY_DELAY_MS,
      DEFAULT_TRUST_CHAIN_RETRY_DELAY_MS
    );

    if (isHttpUrl(entityId) || isHttpUrl(trustAnchorUrl)) {
      app.decorate('trustChain', [INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER]);
      app.decorate('trustChainSource', 'local-dev');
      return;
    }

    // During bootstrap, the RP is not yet listening, so we can't fetch the trust chain yet.
    // We'll attempt the fetch after the server is ready (in the onReady hook).
    // For now, use a signed local-dev JWT as a placeholder.
    let trustChainFetched = false;
    // let trustChainValue: string[] = []; // Removed unused variable

    // Initialize with a signed placeholder
    const initialLocalDevJwt = await generateLocalDevTrustChainJwt({
      entityId,
      trustAnchorUrl,
      authRequestPrivateKeyPem: app.rpKeys.authRequestPrivateKeyPem,
      authResponsePrivateKeyPem: app.rpKeys.authResponsePrivateKeyPem,
      federationPrivateKeyPem: app.rpKeys.federationPrivateKeyPem,
      x5cCertPem: app.rpKeys.x5cCertPem
    });
    app.decorate('trustChain', [initialLocalDevJwt]);
    app.decorate('trustChainSource', 'local-dev');

    // After the server is listening, try to fetch the real trust chain.
    // onReady runs before listen(), which is too early for self-fetch.
    app.addHook('onListen', async () => {
      if (trustChainFetched) {
        return; // Already fetched
      }

      let lastError: unknown;

      for (let attempt = 1; attempt <= maxRetries; attempt += 1) {
        try {
          const trustChain = await fetchTrustChain({
            entityId,
            logger: app.log,
            timeoutMs,
            trustAnchorUrl
          });

          if (trustChain.length === 0) {
            trustChainFetched = true;
            return;
          }

          app.trustChain = trustChain;
          app.trustChainSource = 'real';
          // trustChainValue = trustChain; // Removed unused variable assignment
          trustChainFetched = true;
          return;
        } catch (err) {
          lastError = err;

          if (attempt < maxRetries) {
            await waitMs(retryDelayMs);
          }
        }
      }

      trustChainFetched = true;
      void lastError;
    });
  },
  { name: 'trust-chain', dependencies: ['config', 'keys'] }
);
