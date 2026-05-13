import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { FederationService } from '../federation-service.js';

import type { JwksRepository } from '../../signer.js';

async function makeJwksRepo(): Promise<JwksRepository> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  const kidPub = { ...pub, alg: 'ES256', kid: 'test', kty: 'EC' as const };
  const kidPriv = { ...priv, alg: 'ES256', kid: 'test', kty: 'EC' as const };
  return {
    getEncrypt: vi.fn().mockReturnValue({ private: kidPriv, public: kidPub }),
    getSign: vi.fn().mockReturnValue({ private: kidPriv, public: kidPub }),
    iacaX509: vi.fn().mockReturnValue(''),
  };
}

describe('FederationService', () => {
  it('returns a JWT string (3 dot-separated parts)', async () => {
    const jwksRepo = await makeJwksRepo();
    const svc = new FederationService(jwksRepo);
    const config = { isVersion: vi.fn().mockReturnValue(false) } as never;

    const result = await svc.getEntityConfiguration('https://example.com', config);
    expect(result).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
  });
});

