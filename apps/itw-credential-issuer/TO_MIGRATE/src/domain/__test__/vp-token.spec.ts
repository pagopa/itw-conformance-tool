import type { Openid4vpAuthorizationRequestPayload, ParseAuthorizationResponseResult } from '@pagopa/io-wallet-oid4vp';

import { appContext } from '@/app/context';
import { DataItem, cborDecode, cborEncode } from '@owf/mdoc';
import { createHash } from 'crypto';
import { calculateJwkThumbprint } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { VpTokenVerifier } from '../vp-token';

const { verifyDeviceResponse } = vi.hoisted(() => ({
  verifyDeviceResponse: vi.fn()
}));

vi.mock('@owf/mdoc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@owf/mdoc')>();

  return {
    ...actual,
    Verifier: {
      ...actual.Verifier,
      verifyDeviceResponse
    }
  };
});

describe('VpTokenVerifier', () => {
  const verifierEncryptionPublicJwk = appContext.repository.jwks.getEncrypt().public;
  const requestObject = {
    client_id: `x509_hash:${appContext.config.baseURL}`,
    dcql_query: {
      credentials: [
        {
          format: 'mso_mdoc',
          id: '0'
        }
      ]
    },
    nonce: 'request-nonce',
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${appContext.config.baseURL}/presentation-response?request_uri=test`,
    state: 'test-state'
  } as unknown as Openid4vpAuthorizationRequestPayload;
  const authResponse = {
    authorizationResponsePayload: {
      state: 'test-state',
      vp_token: {
        '0': 'AQ'
      }
    },
    expectedNonce: 'expected-nonce'
  } as unknown as ParseAuthorizationResponseResult;

  beforeEach(() => {
    vi.clearAllMocks();
    verifyDeviceResponse.mockResolvedValue(undefined);
  });

  it('builds the OpenID4VP handover transcript for mdoc verification', async () => {
    const verifier = new VpTokenVerifier({
      authResponse,
      iacaX509: appContext.repository.jwks.iacaX509(),
      requestObject,
      verifierEncryptionPublicJwk
    });

    await verifier.verifyCredentials();

    expect(verifyDeviceResponse).toHaveBeenCalledTimes(1);

    const [{ sessionTranscript }] = verifyDeviceResponse.mock.calls[0];
    const thumbprint = await calculateJwkThumbprint(verifierEncryptionPublicJwk);
    const expectedHandoverInfo = [
      requestObject.client_id,
      authResponse.expectedNonce,
      new Uint8Array(Buffer.from(thumbprint, 'base64url')),
      requestObject.response_uri
    ];
    const expectedHash = new Uint8Array(
      createHash('sha256')
        .update(cborEncode(DataItem.fromData(expectedHandoverInfo)))
        .digest()
    );

    expect(cborDecode(sessionTranscript)).toEqual([null, null, ['OpenID4VPHandover', expectedHash]]);
  });

  it('fails when both response_uri and redirect_uri are missing', async () => {
    const verifier = new VpTokenVerifier({
      authResponse,
      iacaX509: appContext.repository.jwks.iacaX509(),
      requestObject: {
        client_id: requestObject.client_id,
        dcql_query: requestObject.dcql_query,
        iss: requestObject.client_id,
        nonce: requestObject.nonce,
        response_mode: requestObject.response_mode,
        response_type: requestObject.response_type,
        state: requestObject.state
      } as unknown as Openid4vpAuthorizationRequestPayload,
      verifierEncryptionPublicJwk
    });

    await expect(verifier.verifyCredentials()).rejects.toThrow(
      'OID4VP request object is missing both redirect_uri and response_uri'
    );
    expect(verifyDeviceResponse).not.toHaveBeenCalled();
  });
});
