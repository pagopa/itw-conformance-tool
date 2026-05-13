import type { HttpHandler } from '@azure/functions';
import type { HttpMethod } from '@pagopa/io-wallet-utils';

import { CreateCredentialError, InvalidProofError, createCredential } from '@/domain/credential';

import { createErrorResponse, createGenericErrorResponse, createInvalidProofResponse } from './errors/error';

/**
 * Azure Function HTTP handler for POST /credential.
 * Handles incoming credential issuance requests, delegates to the core logic, and formats the HTTP response.
 */
export const PostCredentialResponseHandler: HttpHandler = async (request, context) => {
  const bodyString = await request.text();

  try {
    const { credentialResponse } = await createCredential({
      baseURL: context.app.config.baseURL,
      body: bodyString,
      callbacks: context.app.callbacks,
      config: context.app.sdkConfig,
      headers: request.headers as Headers,
      jwksRepository: context.app.repository.jwks,
      method: request.method as HttpMethod,
      nonceRepository: context.app.repository.nonce,
      url: request.url
    });

    return {
      headers: {
        'Content-Type': 'application/json'
      },
      jsonBody: credentialResponse,
      status: 200
    };
  } catch (err) {
    context.error('Error: ', err instanceof Error ? err.message : String(err));

    if (err instanceof InvalidProofError) {
      return createInvalidProofResponse(err.message);
    }

    if (err instanceof CreateCredentialError) {
      return createErrorResponse({
        error: 'invalid_request',
        error_description: err.message,
        status: 400
      });
    }

    return createGenericErrorResponse(err.message);
  }
};
