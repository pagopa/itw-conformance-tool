import type { HttpRequest, HttpResponseInit, InvocationContext } from '@azure/functions';

import {
  CreateAccessTokenError,
  InvalidGrantError,
  UnsupportedGrantTypeError,
  createAccessToken
} from '@/domain/token';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PostTokenResponseHandler } from '../post-token-response';

vi.mock('@/domain/token', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/domain/token')>();
  return {
    ...actual,
    createAccessToken: vi.fn()
  };
});

describe('PostTokenResponseHandler', () => {
  const mockContext: InvocationContext = {
    app: {
      callbacks: {},
      config: {
        baseURL: 'https://issuer.example.com',
        sdkConfig: {}
      },
      repository: {
        jwks: {},
        par: {}
      }
    },
    error: vi.fn(),
    log: vi.fn()
  } as unknown as InvocationContext;

  const mockRequest = {
    headers: new Headers({
      'content-type': 'application/x-www-form-urlencoded'
    }),
    method: 'POST',
    text: vi.fn().mockResolvedValue('code=abc&code_verifier=verifier&grant_type=authorization_code'),
    url: 'https://issuer.example.com/token'
  } as unknown as HttpRequest;

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should return 400 invalid_grant when the code is invalid', async () => {
    vi.mocked(createAccessToken).mockRejectedValueOnce(
      new InvalidGrantError('Authorization code has already been used: abc')
    );

    const response: HttpResponseInit = await PostTokenResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(400);
    expect(response.jsonBody).toMatchObject({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used: abc'
    });
  });

  it('should return 400 unsupported_grant_type when the grant type is invalid', async () => {
    vi.mocked(createAccessToken).mockRejectedValueOnce(
      new UnsupportedGrantTypeError('Unsupported grant type: refresh_token')
    );

    const response: HttpResponseInit = await PostTokenResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(400);
    expect(response.jsonBody).toMatchObject({
      error: 'unsupported_grant_type',
      error_description: 'Unsupported grant type: refresh_token'
    });
  });

  it('should return 500 for unexpected domain errors', async () => {
    vi.mocked(createAccessToken).mockRejectedValueOnce(new CreateAccessTokenError('unexpected'));

    const response: HttpResponseInit = await PostTokenResponseHandler(mockRequest, mockContext);

    expect(response.status).toBe(500);
    expect(response.jsonBody).toMatchObject({
      error: 'server error',
      error_description: 'unexpected'
    });
  });
});
