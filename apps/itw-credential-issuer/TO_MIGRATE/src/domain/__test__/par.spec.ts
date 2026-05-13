import { getSdkConfig } from '@/domain/sdk-config';
import { decodeJwt, parsePushedAuthorizationRequest, verifyPushedAuthorizationRequest } from '@pagopa/io-wallet-oauth2';
import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { randomUUID } from 'crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { callbacks } from '../crypto';
import { verifyAndSaveParRequest } from '../par';
import { JwksRepository } from '../signer';

vi.mock('@pagopa/io-wallet-oauth2', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@pagopa/io-wallet-oauth2')>();
  return {
    ...actual,
    decodeJwt: vi.fn(),
    parsePushedAuthorizationRequest: vi.fn(),
    verifyPushedAuthorizationRequest: vi.fn()
  };
});

vi.mock('crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('crypto')>();
  return {
    ...actual,
    randomUUID: vi.fn()
  };
});

const dpopJwk = {
  crv: 'P-256',
  d: 'IfSdct8njqWDcMaLIO3ZGG-8a61t9acXxxFWFVDFx6Y',
  kid: '_2WG3zgh4XGrlTCK9QkPoGS-pqAvmg5CcGH_m4eve2e',
  kty: 'EC' as const,
  x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
  y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE'
};
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const { d: __, ...dpopJwkPublic } = dpopJwk;

const mockParRequestRepository = {
  consumeByCode: vi.fn(),
  delete: vi.fn(),
  get: vi.fn(),
  insert: vi.fn(),
  update: vi.fn()
};

const mockJwksRepository: JwksRepository = {
  getEncrypt: () => ({
    private: dpopJwk,
    public: dpopJwkPublic
  }),
  getSign: () => ({
    private: dpopJwk,
    public: dpopJwkPublic
  }),
  iacaX509: () => 'iacaX509'
};

describe('verifyAndSaveParRequest', () => {
  const baseURL = 'https://example.com';
  const bodyString = 'client_id=test_client&request=test_jwt_request';
  const headers = new Headers({
    'content-type': 'application/x-www-form-urlencoded',
    dpop: 'mock-dpop-jwt'
  });
  const method = 'POST';
  const url = `${baseURL}/par`;

  const mockAuthorizationRequest = {
    authorization_details: [
      {
        credential_configuration_id: 'test_config',
        type: 'openid_credential'
      }
    ],
    client_id: 'test_client',
    code_challenge: 'test_challenge',
    code_challenge_method: 'S256',
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    redirect_uri: 'https://example.com/callback',
    response_mode: 'query',
    response_type: 'vp_token',
    state: 'test_state'
  };

  const mockGeneratedId = 'b2c3d4e5-f6a7-8901-2345-67890abcdef0';
  const mockGeneratedRequestUri = 'a1b2c3d4-e5f6-7890-1234-567890abcdef';

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should successfully verify and save a PAR request', async () => {
    mockParRequestRepository.get.mockResolvedValue(undefined);
    mockParRequestRepository.insert.mockResolvedValue('mock_request_uri');

    vi.mocked(randomUUID)
      .mockReturnValueOnce(mockGeneratedRequestUri as ReturnType<typeof randomUUID>)
      .mockReturnValueOnce(mockGeneratedId as ReturnType<typeof randomUUID>);

    vi.mocked(parsePushedAuthorizationRequest).mockResolvedValue({
      authorizationRequest: mockAuthorizationRequest,
      authorizationRequestJwt: 'test_jwt_request',
      clientAttestation: {
        walletAttestationJwt: 'wallet_attestation_jwt'
      }
    } as never);

    vi.mocked(decodeJwt).mockReturnValue({
      payload: {
        cnf: {
          jwk: dpopJwkPublic
        }
      }
    } as never);

    vi.mocked(verifyPushedAuthorizationRequest).mockResolvedValue(undefined as never);

    const result = await verifyAndSaveParRequest({
      baseURL,
      callbacks,
      config: getSdkConfig(ItWalletSpecsVersion.V1_0),
      jwksRepository: mockJwksRepository,
      parRequest: {
        bodyString,
        headers,
        method,
        url
      },
      parRequestRepository: mockParRequestRepository
    });

    expect(decodeJwt).toHaveBeenCalledWith({
      jwt: 'wallet_attestation_jwt'
    });
    expect(parsePushedAuthorizationRequest).toHaveBeenCalled();
    expect(verifyPushedAuthorizationRequest).toHaveBeenCalled();
    expect(mockParRequestRepository.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        client_id: 'test_client',
        id: mockGeneratedId,
        request_uri: 'urn:ietf:params:oauth:request_uri:' + mockGeneratedRequestUri
      })
    );
    expect(result).toBe('urn:ietf:params:oauth:request_uri:' + mockGeneratedRequestUri);
  });

  it('should throw an error if oauth.verifyPushedAuthorizationRequest fails', async () => {
    mockParRequestRepository.get.mockResolvedValue(undefined);

    vi.mocked(randomUUID).mockReturnValueOnce('a1b2c3d4-e5f6-7890-1234-567890abcdef' as ReturnType<typeof randomUUID>);

    vi.mocked(parsePushedAuthorizationRequest).mockResolvedValue({
      authorizationRequest: mockAuthorizationRequest,
      authorizationRequestJwt: 'test_jwt_request',
      clientAttestation: {
        walletAttestationJwt: 'wallet_attestation_jwt'
      }
    } as never);

    vi.mocked(decodeJwt).mockReturnValue({
      payload: {
        cnf: {
          jwk: dpopJwkPublic
        }
      }
    } as never);

    vi.mocked(verifyPushedAuthorizationRequest).mockRejectedValue(new Error('Verification failed'));

    await expect(
      verifyAndSaveParRequest({
        baseURL,
        callbacks,
        config: getSdkConfig(ItWalletSpecsVersion.V1_0),
        jwksRepository: mockJwksRepository,
        parRequest: {
          bodyString,
          headers,
          method,
          url
        },
        parRequestRepository: mockParRequestRepository
      })
    ).rejects.toThrow('Verification failed');

    expect(parsePushedAuthorizationRequest).toHaveBeenCalled();
    expect(verifyPushedAuthorizationRequest).toHaveBeenCalled();
    expect(mockParRequestRepository.insert).not.toHaveBeenCalled();
  });
});
