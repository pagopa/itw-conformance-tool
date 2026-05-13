import type { HttpHandler } from '@azure/functions';

import { generateNonce } from '@/domain/nonce';

import { createGenericErrorResponse } from './errors/error';

/**
 * Azure Function handler for creating and returning a new nonce.
 *
 * @param request - The incoming HTTP request.
 * @param context - Azure function invocation context.
 * @returns HTTP response containing the nonce or an error message.
 */
export const PostNonceResponseHandler: HttpHandler = async (_request, context) => {
  try {
    const nonce = await generateNonce({
      nonceRepository: context.app.repository.nonce
    });

    return {
      body: JSON.stringify({
        c_nonce: nonce
      }),
      headers: {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json'
      },
      status: 200
    };
  } catch (err) {
    context.error('Error: ', err.message);
    return createGenericErrorResponse(err.message);
  }
};
