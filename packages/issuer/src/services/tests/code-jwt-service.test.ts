import { decodeJwt, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { AUTHORIZATION_CODE_TTL_SECONDS } from '../../models/token.js';
import { CodeJwtService, InvalidRequestUriError } from '../code-jwt-service.js';

import type { JwksRepository } from '../../signer.js';
import type { ICodeJwtParEntry, ICodeJwtParRepository } from '../code-jwt-service.js';

function makeParRepo(overrides: Partial<ICodeJwtParRepository> = {}): ICodeJwtParRepository {
  return {
    get: vi.fn().mockResolvedValue(undefined),
    setCode: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
}

async function makeJwksRepo(): Promise<JwksRepository> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(publicKey);
  const priv = await exportJWK(privateKey);
  const kidPub = { ...pub, alg: 'ES256', kid: 'test', kty: 'EC' as const };
  const kidPriv = { ...priv, alg: 'ES256', kid: 'test', kty: 'EC' as const };
  return {
    getEncrypt: vi.fn().mockReturnValue({ private: kidPriv, public: kidPub }),
    getSign: vi.fn().mockReturnValue({ private: kidPriv, public: kidPub }),
    iacaX509: vi.fn().mockReturnValue('')
  };
}

describe('CodeJwtService', () => {
  it('throws InvalidRequestUriError when request_uri is unknown', async () => {
    const repo = makeParRepo({ get: vi.fn().mockResolvedValue(undefined) });
    const svc = new CodeJwtService({
      baseURL: 'https://issuer.example',
      jwksRepository: await makeJwksRepo(),
      parRepository: repo
    });

    await expect(svc.createAuthorizationCodeJwt('urn:missing')).rejects.toBeInstanceOf(InvalidRequestUriError);
    expect(repo.setCode).not.toHaveBeenCalled();
  });

  it('persists generated code/expiry and returns a form_post for the redirect_uri', async () => {
    const parEntry: ICodeJwtParEntry = {
      clientId: 'client',
      redirectUri: 'https://wallet.example/callback',
      requestUri: 'urn:test',
      state: 'state-1'
    };

    const repo = makeParRepo({
      get: vi.fn().mockResolvedValue(parEntry)
    });
    const svc = new CodeJwtService({
      baseURL: 'https://issuer.example',
      jwksRepository: await makeJwksRepo(),
      parRepository: repo
    });

    const before = Math.floor(Date.now() / 1000);
    const result = await svc.createAuthorizationCodeJwt(parEntry.requestUri);
    const after = Math.floor(Date.now() / 1000);

    expect(repo.setCode).toHaveBeenCalledOnce();
    const [requestUri, generatedCode, codeExpiresAt] = (repo.setCode as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      string,
      number
    ];

    expect(requestUri).toBe(parEntry.requestUri);
    expect(generatedCode).toBeTypeOf('string');
    expect(generatedCode.length).toBeGreaterThan(0);
    expect(codeExpiresAt).toBeGreaterThanOrEqual(before + AUTHORIZATION_CODE_TTL_SECONDS);
    expect(codeExpiresAt).toBeLessThanOrEqual(after + AUTHORIZATION_CODE_TTL_SECONDS + 1);

    expect(result.redirectUri).toBe(parEntry.redirectUri);
    expect(result.formPost).toContain(`action="${parEntry.redirectUri}"`);

    const jwtMatch = result.formPost.match(/name="response" value="([^"]+)"/);
    expect(jwtMatch?.[1]).toBeTruthy();
    const payload = decodeJwt(jwtMatch?.[1] ?? '');
    expect(payload.code).toBe(generatedCode);
    expect(payload.state).toBe(parEntry.state);
    expect(payload.exp).toBe(codeExpiresAt);
  });
});
