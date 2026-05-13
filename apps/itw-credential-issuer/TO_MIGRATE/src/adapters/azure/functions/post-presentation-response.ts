import type { HttpHandler } from '@azure/functions';

import { getDecryptJweCallback } from '@/domain/crypto';
import { VpTokenVerifier } from '@/domain/vp-token';
import { parseAuthorizationResponse } from '@pagopa/io-wallet-oid4vp';

import { createErrorResponse, createGenericErrorResponse } from './errors/error';

export const PostPresentationResponseHandler: HttpHandler = async (request, context) => {
  const body = await request.text();
  const request_uri = request.query.get('request_uri');

  if (!request_uri) {
    return createErrorResponse({
      error: 'invalid_request',
      error_description: 'client_id and request_uri are required',
      status: 400
    });
  }

  try {
    const parRequest = await context.app.repository.par.get({
      requestUri: request_uri
    });

    if (!parRequest) {
      return createErrorResponse({
        error: 'invalid_request',
        error_description: 'request_uri not found',
        status: 400
      });
    }

    const iacaX509 = context.app.repository.jwks.iacaX509();
    const encryptionKey = context.app.repository.jwks.getEncrypt().private;
    const requestObject = parRequest.oid4vpRequestObject;

    const authResponse = await parseAuthorizationResponse({
      authorizationRequestPayload: requestObject,
      authorizationResponse: Object.fromEntries(new URLSearchParams(body).entries()),
      // @ts-expect-error verifyJwt callback is only required for signed JWT but
      // we are only dealing with encrypted JWTs here according to IT Wallet specs
      callbacks: {
        decryptJwe: getDecryptJweCallback(encryptionKey)
      }
    });

    // Verify all credentials according to their DCQL-specified format
    const verifier = new VpTokenVerifier({
      authResponse,
      iacaX509,
      requestObject,
      verifierEncryptionPublicJwk: context.app.repository.jwks.getEncrypt().public
    });

    await verifier.verifyCredentials();

    return {
      jsonBody: {
        redirect_uri: `${context.app.config.baseURL}/authorization-code?request_uri=${request_uri}`
      },
      status: 200
    };
  } catch (err) {
    context.error('Error: ', err.message);
    return createGenericErrorResponse(err.message);
  }
};
