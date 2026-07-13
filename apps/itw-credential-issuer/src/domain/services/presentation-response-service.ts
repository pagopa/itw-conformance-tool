import { parseAuthorizationResponse } from '@pagopa/io-wallet-oid4vp';

import { getDecryptJweCallback } from '../crypto.js';

import type { JwksRepository } from '../signer.js';
import type { ParRequest } from '../z-par.js';
import type { IPARRepository } from '@itw-conformance-tool/database';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';

export class PresentationResponseError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'PresentationResponseError';
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, PresentationResponseError.prototype);
  }
}

export type HandlePresentationResponseOptions = {
  readonly baseURL: string;
  readonly callbacks: Pick<CallbackContext, 'verifyJwt'>;
  readonly bodyString: string;
  readonly requestUri: string;
};

export class PresentationResponseService {
  readonly #parRepository: IPARRepository;
  readonly #jwksRepository: JwksRepository;

  constructor(parRepository: IPARRepository, jwksRepository: JwksRepository) {
    this.#parRepository = parRepository;
    this.#jwksRepository = jwksRepository;
  }

  async handle(options: HandlePresentationResponseOptions): Promise<{ readonly redirectUri: string }> {
    const entry = await this.#parRepository.get(options.requestUri);
    if (!entry) {
      throw new PresentationResponseError('request_uri not found');
    }

    const parRequest = JSON.parse(entry.requestObject) as ParRequest;
    if (!parRequest.oid4vpRequestObject) {
      throw new PresentationResponseError('OID4VP request object not found for request_uri');
    }

    await parseAuthorizationResponse({
      authorizationRequestPayload: parRequest.oid4vpRequestObject,
      authorizationResponse: Object.fromEntries(new URLSearchParams(options.bodyString).entries()),
      callbacks: {
        decryptJwe: getDecryptJweCallback(this.#jwksRepository.getEncrypt().private),
        verifyJwt: options.callbacks.verifyJwt
      }
    });

    return {
      redirectUri: new URL(
        `/code/jwt?request_uri=${encodeURIComponent(options.requestUri)}`,
        options.baseURL
      ).toString()
    };
  }
}
