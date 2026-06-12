import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

const mocked = vi.hoisted(() => ({
  fetchAndValidateTrustChain: vi.fn()
}));

vi.mock('@pagopa/io-wallet-oid-federation', () => ({
  fetchAndValidateTrustChain: mocked.fetchAndValidateTrustChain
}));

import { fetchTrustChain } from '../../trust-chain/fetch-trust-chain.js';

describe('fetchTrustChain', () => {
  const entityId = 'https://rp.example.org';
  const trustAnchorUrl = 'https://trust-anchor.example.org/.well-known/openid-federation';
  const logger = {
    info: vi.fn<(obj: Record<string, unknown>, msg?: string) => void>(),
    warn: vi.fn<(obj: Record<string, unknown>, msg?: string) => void>()
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches and returns a non-empty trust chain', async () => {
    mocked.fetchAndValidateTrustChain.mockResolvedValue(['leaf.jwt', 'anchor.jwt']);

    const trustChain = await fetchTrustChain({
      entityId,
      trustAnchorUrl,
      logger,
      timeoutMs: 3210
    });

    expect(trustChain).toEqual(['leaf.jwt', 'anchor.jwt']);
    expect(mocked.fetchAndValidateTrustChain).toHaveBeenCalledTimes(1);
    expect(mocked.fetchAndValidateTrustChain).toHaveBeenCalledWith(
      'https://rp.example.org',
      expect.objectContaining({
        trustAnchorUrls: ['https://trust-anchor.example.org']
      })
    );
  });

  it('normalizes trust anchor URLs ending with /.well-known/openid-federation/', async () => {
    mocked.fetchAndValidateTrustChain.mockResolvedValue(['leaf.jwt', 'anchor.jwt']);

    await fetchTrustChain({
      entityId,
      trustAnchorUrl: 'https://trust-anchor.example.org/.well-known/openid-federation/',
      logger
    });

    expect(mocked.fetchAndValidateTrustChain).toHaveBeenCalledWith(
      'https://rp.example.org',
      expect.objectContaining({
        trustAnchorUrls: ['https://trust-anchor.example.org']
      })
    );
  });

  it('resolves relative trust anchor URLs against entityId origin', async () => {
    mocked.fetchAndValidateTrustChain.mockResolvedValue(['leaf.jwt', 'anchor.jwt']);

    await fetchTrustChain({
      entityId,
      trustAnchorUrl: '/.well-known/openid-federation',
      logger
    });

    expect(mocked.fetchAndValidateTrustChain).toHaveBeenCalledWith(
      'https://rp.example.org',
      expect.objectContaining({
        trustAnchorUrls: ['https://rp.example.org']
      })
    );
  });

  it('provides a fetch callback that applies a timeout', async () => {
    mocked.fetchAndValidateTrustChain.mockImplementation(
      async (_url: string, options: { callbacks: { fetch: typeof fetch } }) => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 200 })));

        await options.callbacks.fetch('https://resolver.example.org/resolve');
        return ['leaf.jwt'];
      }
    );

    await fetchTrustChain({
      entityId,
      trustAnchorUrl,
      logger,
      timeoutMs: 1234
    });

    expect(fetch).toHaveBeenCalledWith(
      'https://resolver.example.org/resolve',
      expect.objectContaining({
        signal: expect.any(AbortSignal)
      })
    );
  });

  it('fails when trust chain resolution returns an empty chain', async () => {
    mocked.fetchAndValidateTrustChain.mockResolvedValue([]);

    const result = await fetchTrustChain({
      entityId,
      trustAnchorUrl,
      logger
    });

    expect(result).toEqual([]);
    expect(logger.warn).toHaveBeenCalledTimes(0);
  });

  it('returns default chain on resolver errors', async () => {
    mocked.fetchAndValidateTrustChain.mockRejectedValue(new Error('resolver unavailable'));

    const result = await fetchTrustChain({
      entityId,
      trustAnchorUrl,
      logger
    });

    expect(result).toEqual([]);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith({}, 'Unable to fetch and validate trust chain');
  });
});
