import { describe, expect, it, vi } from 'vitest';

import { AuthorizationService } from '../authorization-service.js';

import type { IPARRepository } from '@itw-conformance-tool/database';

function makeParRepository(requestObject: Record<string, unknown>): IPARRepository {
  return {
    delete: vi.fn().mockResolvedValue(undefined),
    get: vi.fn().mockResolvedValue({
      clientId: 'wallet-client',
      expiresAt: Date.now() + 60_000,
      requestObject: JSON.stringify(requestObject),
      requestUri: 'urn:ietf:params:oauth:request_uri:test'
    }),
    getByMrtdAuthSession: vi.fn().mockResolvedValue(undefined),
    insert: vi.fn().mockResolvedValue(undefined),
    update: vi.fn().mockResolvedValue(undefined)
  };
}

function makeService(parRepository: IPARRepository): AuthorizationService {
  const jwksRepository = {
    getEncrypt: vi.fn(),
    getSign: vi.fn(),
    iacaX509: vi.fn()
  } as never;

  return new AuthorizationService(parRepository, jwksRepository);
}

function makePidParRequest(): Record<string, unknown> {
  return {
    authorization_details: [
      {
        credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData',
        type: 'openid_credential'
      }
    ],
    client_id: 'wallet-client',
    redirect_uri: 'https://wallet.example/callback',
    request_uri: 'urn:ietf:params:oauth:request_uri:test',
    state: 'state-123'
  };
}

describe('AuthorizationService PID dispatch', () => {
  it('keeps legacy direct flow when authFlow is omitted', async () => {
    const parRepository = makeParRepository(makePidParRequest());
    const service = makeService(parRepository);

    const result = await service.authorize({
      baseURL: 'https://issuer.example',
      callbacks: { encryptJwe: vi.fn() },
      clientId: 'wallet-client',
      config: { isVersion: vi.fn().mockReturnValue(false) } as never,
      requestUri: 'urn:ietf:params:oauth:request_uri:test'
    });

    expect(result.kind).toBe('redirect');
    expect(parRepository.update).toHaveBeenCalledOnce();

    const [, payload] = (parRepository.update as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      { requestObject: string }
    ];
    const updated = JSON.parse(payload.requestObject);

    expect(updated.pid_auth_flow).toBe('direct');
    expect(updated.code).toBeTypeOf('string');
    expect(updated.code_expires_at).toBeTypeOf('number');
  });

  it('redirects PID flow to mock IdP when authFlow is l2plus', async () => {
    const parRepository = makeParRepository(makePidParRequest());
    const service = makeService(parRepository);

    const result = await service.authorize({
      authFlow: 'l2plus',
      baseURL: 'https://issuer.example',
      callbacks: { encryptJwe: vi.fn() },
      clientId: 'wallet-client',
      config: { isVersion: vi.fn().mockReturnValue(false) } as never,
      requestUri: 'urn:ietf:params:oauth:request_uri:test'
    });

    expect(result.kind).toBe('redirect');
    if (result.kind !== 'redirect') {
      throw new Error('Expected redirect response');
    }

    const redirectUrl = new URL(result.location);
    expect(redirectUrl.pathname).toBe('/idp/authorize');
    expect(redirectUrl.searchParams.get('request_uri')).toBe('urn:ietf:params:oauth:request_uri:test');

    const [, payload] = (parRepository.update as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      { requestObject: string }
    ];
    const updated = JSON.parse(payload.requestObject);

    expect(updated.pid_auth_flow).toBe('l2plus');
    expect(updated.code).toBeUndefined();
    expect(updated.code_expires_at).toBeUndefined();
  });

  it('redirects PID flow to mock IdP when authFlow is l3', async () => {
    const parRepository = makeParRepository(makePidParRequest());
    const service = makeService(parRepository);

    const result = await service.authorize({
      authFlow: 'l3',
      baseURL: 'https://issuer.example',
      callbacks: { encryptJwe: vi.fn() },
      clientId: 'wallet-client',
      config: { isVersion: vi.fn().mockReturnValue(false) } as never,
      requestUri: 'urn:ietf:params:oauth:request_uri:test'
    });

    expect(result.kind).toBe('redirect');
    if (result.kind !== 'redirect') {
      throw new Error('Expected redirect response');
    }

    const redirectUrl = new URL(result.location);
    expect(redirectUrl.pathname).toBe('/idp/authorize');
    expect(redirectUrl.searchParams.get('request_uri')).toBe('urn:ietf:params:oauth:request_uri:test');

    const [, payload] = (parRepository.update as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      { requestObject: string }
    ];
    const updated = JSON.parse(payload.requestObject);

    expect(updated.pid_auth_flow).toBe('l3');
    expect(updated.code).toBeUndefined();
    expect(updated.code_expires_at).toBeUndefined();
  });
});
