import type { ParRequestRepository } from '@/domain/par';
import type { JwksRepository } from '@/domain/signer';
import type { HttpRequest, HttpResponseInit, InvocationContext } from '@azure/functions';

import { callbacks } from '@/domain/crypto';
import { randomUUID } from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { GetAuthorizationResponseHandler } from '../get-authorization-response';

vi.mock('crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('crypto')>();
  return {
    ...actual,
    randomUUID: vi.fn()
  };
});

const mockParRequestRepository: ParRequestRepository = {
  consumeByCode: vi.fn(),
  get: vi.fn(),
  insert: vi.fn(),
  update: vi.fn()
};

const mockJwkRepository: JwksRepository = {
  getEncrypt: vi.fn(),
  getSign: vi.fn(),
  iacaX509: vi.fn()
};

describe('GetAuthorizationResponse', () => {
  const mockContext: InvocationContext = {
    app: {
      callbacks,
      config: {
        baseURL: 'https://example.com'
      },
      repository: {
        jwks: mockJwkRepository,
        par: mockParRequestRepository
      }
    },
    error: vi.fn(),
    log: vi.fn()
  } as unknown as InvocationContext;

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should return 400 if client_id or request_uri is missing', async () => {
    const mockRequest = {
      query: new Map()
    } as unknown as HttpRequest;

    const response: HttpResponseInit = await GetAuthorizationResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(400);
    expect(response.jsonBody).toMatchObject({
      error: 'invalid_request',
      error_description: 'client_id and request_uri are required'
    });
  });

  it('should return 400 if request_uri is not found', async () => {
    const mockRequest = {
      query: new Map([
        ['client_id', 'test_client'],
        ['request_uri', 'test_request_uri']
      ])
    } as unknown as HttpRequest;

    vi.mocked(mockParRequestRepository.get).mockResolvedValue(null);

    const response: HttpResponseInit = await GetAuthorizationResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(400);
    expect(response.jsonBody).toMatchObject({
      error: 'invalid_request',
      error_description: 'request_uri not found'
    });
  });

  it('should return 302 with a valid authorization code', async () => {
    vi.mocked(randomUUID).mockReturnValue('11111111-1111-1111-1111-111111111111');
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);

    const mockRequest = {
      query: new Map([
        ['client_id', 'test_client'],
        ['request_uri', 'test_request_uri']
      ])
    } as unknown as HttpRequest;

    vi.mocked(mockParRequestRepository.get).mockResolvedValue({
      authorization_details: [
        {
          credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData',
          type: 'openid_credential'
        }
      ],
      client_id: 'test_client',
      code_challenge: 'test_code_challenge',
      code_challenge_method: 'S256',
      id: 'test_id',
      jti: 'test_jti',
      redirect_uri: 'https://example.com/callback',
      request_uri: 'test_request_uri',
      response_type: 'code',
      state: 'test_state'
    });
    vi.mocked(mockParRequestRepository.update).mockResolvedValue();

    const response = await GetAuthorizationResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(302);
    expect(response.headers?.['Location']).toContain('https://example.com/callback');
    expect(response.headers?.['Location']).toContain('code=11111111-1111-1111-1111-111111111111');
    expect(response.headers?.['Location']).toContain('state=test_state');
    expect(mockParRequestRepository.update).toHaveBeenCalledWith(
      expect.objectContaining({
        code: '11111111-1111-1111-1111-111111111111',
        code_expires_at: 1_700_000_060
      })
    );
  });
});
