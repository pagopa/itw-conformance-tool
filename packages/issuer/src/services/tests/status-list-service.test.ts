import { decodeJwt, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { STATUS_LIST_TTL_SECONDS } from '../../models/status-list.js';
import { STATUS_LIST_URI } from '../../utils/status-list.js';
import { StatusListService } from '../status-list-service.js';

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
    iacaX509: vi.fn().mockReturnValue('mock-cert')
  };
}

describe('StatusListService', () => {
  it('returns a JWT with expected status-list claims and TTL values', async () => {
    const baseURL = 'https://issuer.example';
    const svc = new StatusListService(await makeJwksRepo());

    const jwt = await svc.getStatusListJwt(baseURL);
    expect(jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    const payload = decodeJwt(jwt) as Record<string, unknown>;
    expect(payload.iss).toBe(baseURL);
    expect(payload.sub).toBe(STATUS_LIST_URI(baseURL));
    expect(payload.ttl).toBe(STATUS_LIST_TTL_SECONDS);

    const iat = payload.iat as number;
    const exp = payload.exp as number;
    expect(exp - iat).toBe(STATUS_LIST_TTL_SECONDS);
  });
});
