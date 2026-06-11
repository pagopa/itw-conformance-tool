import fp from 'fastify-plugin';

import { fetchTrustChain } from '../trust-chain/fetch-trust-chain.js';

declare module 'fastify' {
  interface FastifyInstance {
    trustChain: [string, ...string[]];
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

export default fp(
  async function trustChainPlugin(app) {
    const { entityId, trustAnchorUrl } = app.config;
    if (trustAnchorUrl === undefined || trustAnchorUrl.trim().length === 0) {
      app.log.error('Missing Trust Anchor URL: configure [rp].trust_anchor or ITW_CT_RP_TRUST_ANCHOR_URL');
      throw new Error('Trust chain bootstrap failed: Trust Anchor URL is not configured');
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
      app.log.warn(
        {
          entityId,
          trustAnchorUrl
        },
        'Trust chain bootstrap running in insecure HTTP local-dev mode; strict federation validation is skipped'
      );
      return;
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

        app.decorate('trustChain', trustChain);
        app.log.info(
          {
            attempt,
            entityId,
            trustAnchorUrl,
            trustChainLength: trustChain.length
          },
          'Trust chain loaded in memory'
        );
        return;
      } catch (err) {
        lastError = err;

        if (attempt < maxRetries) {
          app.log.warn(
            {
              attempt,
              maxRetries,
              retryDelayMs,
              entityId,
              trustAnchorUrl,
              err
            },
            'Trust chain bootstrap failed, retrying'
          );
          await waitMs(retryDelayMs);
        }
      }
    }

    app.log.error(
      {
        attempts: maxRetries,
        entityId,
        err: lastError,
        trustAnchorUrl
      },
      'Trust chain bootstrap failed after retries; starting in degraded mode without strict federation validation'
    );
    app.decorate('trustChain', [INSECURE_HTTP_TRUST_CHAIN_PLACEHOLDER]);
  },
  { name: 'trust-chain', dependencies: ['config'] }
);
