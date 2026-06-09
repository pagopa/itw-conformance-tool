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
      configFilePath: '/tmp/config.ini',
      signingKeyPath: '/tmp/signing-key.pem',
      x5cCertPath: '/tmp/x5c-cert.pem',
      httpsEnabled: false,
      tlsCertPath: '',
      tlsKeyPath: ''
    });
  },
  { name: 'config' }
);

describe('trust-chain plugin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
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
            trustAnchorUrl: '',
            dataDir: '/tmp',
            configFilePath: '/tmp/config.ini',
            signingKeyPath: '/tmp/signing-key.pem',
            x5cCertPath: '/tmp/x5c-cert.pem',
            httpsEnabled: false,
            tlsCertPath: '',
            tlsKeyPath: ''
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
            configFilePath: '/tmp/config.ini',
            signingKeyPath: '/tmp/signing-key.pem',
            x5cCertPath: '/tmp/x5c-cert.pem',
            httpsEnabled: false,
            tlsCertPath: '',
            tlsKeyPath: ''
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

  it('retries trust chain fetch and succeeds on a subsequent attempt', async () => {
    vi.stubEnv('ITW_CT_TRUST_CHAIN_FETCH_RETRIES', '3');
    vi.stubEnv('ITW_CT_TRUST_CHAIN_FETCH_RETRY_DELAY_MS', '1');

    mocked.fetchTrustChain
      .mockRejectedValueOnce(new Error('resolver timeout'))
      .mockRejectedValueOnce(new Error('resolver timeout'))
      .mockResolvedValueOnce(['leaf.jwt', 'anchor.jwt']);

    const app = Fastify({ logger: false });
    await app.register(configDependencyPlugin);

    await app.register(trustChainPlugin);
    await app.ready();

    expect(mocked.fetchTrustChain).toHaveBeenCalledTimes(3);
    expect(app.trustChain).toEqual(['leaf.jwt', 'anchor.jwt']);
    await app.close();
  });

  it('fails startup after all retry attempts fail', async () => {
    vi.stubEnv('ITW_CT_TRUST_CHAIN_FETCH_RETRIES', '2');
    vi.stubEnv('ITW_CT_TRUST_CHAIN_FETCH_RETRY_DELAY_MS', '1');
    mocked.fetchTrustChain.mockRejectedValue(new Error('resolver unavailable'));

    const app = Fastify({ logger: false });
    await app.register(configDependencyPlugin);

    await expect(app.register(trustChainPlugin)).rejects.toThrow('resolver unavailable');
    expect(mocked.fetchTrustChain).toHaveBeenCalledTimes(2);
    await app.close();
  });
});
