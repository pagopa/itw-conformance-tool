import Fastify from 'fastify';
import fp from 'fastify-plugin';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  fetchTrustChain: vi.fn()
}));

vi.mock('../../trust-chain/fetch-trust-chain.js', () => ({
  fetchTrustChain: mocked.fetchTrustChain
}));

import trustChainPlugin from '../../plugins/trust-chain.js';

const configDependencyPlugin = fp(
  async (app) => {
    app.decorate('config', {
      host: '0.0.0.0',
      port: 8080,
      baseUrl: 'https://rp.example.org',
      entityId: 'https://rp.example.org',
      trustAnchorUrl: 'https://trust-anchor.example.org/.well-known/openid-federation',
      dataDir: '/tmp',
      configFilePath: '/tmp/config.ini'
    });
  },
  { name: 'config' }
);

describe('trust-chain plugin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('decorates app with trust chain at bootstrap', async () => {
    mocked.fetchTrustChain.mockResolvedValue(['leaf.jwt', 'anchor.jwt']);

    const app = Fastify({ logger: false });
    await app.register(configDependencyPlugin);

    await app.register(trustChainPlugin);
    await app.ready();

    expect(app.trustChain).toEqual(['leaf.jwt', 'anchor.jwt']);
    await app.close();
  });

  it('fails fast when trust anchor URL is missing', async () => {
    const app = Fastify({ logger: false });

    await app.register(
      fp(
        async (instance) => {
          instance.decorate('config', {
            host: '0.0.0.0',
            port: 8080,
            baseUrl: 'http://localhost:8080',
            entityId: 'http://localhost:8080',
            trustAnchorUrl: undefined,
            dataDir: '/tmp',
            configFilePath: '/tmp/config.ini'
          });
        },
        { name: 'config' }
      )
    );

    await expect(app.register(trustChainPlugin)).rejects.toThrow(
      'Trust chain bootstrap failed: Trust Anchor URL is not configured'
    );

    await app.close();
  });

  it('accepts HTTP entity and trust anchor URLs in local-dev mode', async () => {
    mocked.fetchTrustChain.mockResolvedValue(['leaf.jwt', 'anchor.jwt']);

    const app = Fastify({ logger: false });

    await app.register(
      fp(
        async (instance) => {
          instance.decorate('config', {
            host: '0.0.0.0',
            port: 8080,
            baseUrl: 'http://localhost:8080',
            entityId: 'http://localhost:8080',
            trustAnchorUrl: 'http://localhost:3000/.well-known/openid-federation',
            dataDir: '/tmp',
            configFilePath: '/tmp/config.ini'
          });
        },
        { name: 'config' }
      )
    );

    await app.register(trustChainPlugin);
    await app.ready();

    expect(mocked.fetchTrustChain).not.toHaveBeenCalled();
    expect(app.trustChain).toEqual(['insecure-http-local-dev']);
    await app.close();
  });
});
