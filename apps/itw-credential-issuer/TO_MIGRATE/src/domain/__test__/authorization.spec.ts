import type { InvocationContext } from '@azure/functions';

import { appContext } from '@/app/context';
import { createAuthorizationRequest } from '@pagopa/io-wallet-oid4vp';
import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { decodeProtectedHeader } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import type { ParRequest } from '../z-par';

import { handleEAAAuthorizationResponse } from '../authorization';
import { getSdkConfig } from '../sdk-config';

vi.mock('../openid-federation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../openid-federation')>();
  return {
    ...actual,
    getFederationMetadata: vi.fn().mockResolvedValue('mock-federation-metadata')
  };
});

vi.mock('@pagopa/io-wallet-oid4vp', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@pagopa/io-wallet-oid4vp')>();
  return {
    ...actual,
    createAuthorizationRequest: vi.fn(async ({ authorizationRequestPayload, callbacks, jar }) => {
      const { jwt } = await callbacks.signJwt(jar.jwtSigner, {
        header: {
          kid: jar.jwtSigner.kid,
          typ: 'oauth-authz-req+jwt',
          ...(jar.jwtSigner.method === 'x5c' ? { x5c: jar.jwtSigner.x5c } : { trust_chain: jar.jwtSigner.trustChain })
        },
        payload: authorizationRequestPayload
      });

      return {
        authorizationRequestPayload,
        jar: {
          authorizationRequestJwt: jwt
        }
      };
    })
  };
});

describe('handleEAAAuthorizationResponse', () => {
  it('returns a v1.3 request object with kid and x5c in the header', async () => {
    const requestUri = 'urn:ietf:params:oauth:request_uri:test';
    const update = vi.fn().mockResolvedValue(undefined);
    const parRequest = {
      state: 'teststate123'
    } as ParRequest;

    const context = {
      app: {
        callbacks: appContext.callbacks,
        config: appContext.config,
        repository: {
          jwks: appContext.repository.jwks,
          par: {
            update
          }
        },
        sdkConfig: getSdkConfig(ItWalletSpecsVersion.V1_3)
      },
      error: vi.fn(),
      log: vi.fn()
    } as unknown as InvocationContext;

    const response = await handleEAAAuthorizationResponse(context, parRequest, requestUri);

    expect(response.status).toBe(200);
    expect(typeof response.body).toBe('string');

    const header = decodeProtectedHeader(response.body as string);

    expect(header.kid).toBe(appContext.repository.jwks.getSign().public.kid);
    expect(header.typ).toBe('oauth-authz-req+jwt');
    expect(header.x5c).toEqual([appContext.repository.jwks.iacaX509()]);
    expect(createAuthorizationRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationRequestPayload: expect.objectContaining({
          client_id: `x509_hash:${appContext.config.baseURL}`
        }),
        jar: expect.objectContaining({
          jwtSigner: expect.objectContaining({
            kid: appContext.repository.jwks.getSign().public.kid,
            method: 'x5c',
            x5c: [appContext.repository.jwks.iacaX509()]
          })
        })
      })
    );
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        oid4vpRequestObject: expect.objectContaining({
          client_id: `x509_hash:${appContext.config.baseURL}`,
          response_mode: 'direct_post.jwt',
          response_type: 'vp_token',
          response_uri: `${appContext.config.baseURL}/presentation-response?request_uri=${requestUri}`,
          state: 'teststate123'
        })
      })
    );
  });
});
