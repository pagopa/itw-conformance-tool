import { randomUUID } from 'node:crypto';

import { parsePushedAuthorizationRequest } from '@pagopa/io-wallet-oauth2';

import { PAR_TTL_MS } from '../models/par-entry.js';
import { getPushedAuthorizationRequestSchema, type ParRequest } from '../z-par.js';

import type { IPARRepository } from '@itw-conformance-tool/database';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';
import type { HttpMethod, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

export class PostPushedAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PostPushedAuthorizationError';
    Object.setPrototypeOf(this, PostPushedAuthorizationError.prototype);
  }
}

export interface ParseAndStoreOptions {
  readonly baseURL: string;
  readonly callbacks: Pick<CallbackContext, 'fetch'>;
  readonly config: IoWalletSdkConfig;
  readonly parRequest: {
    readonly bodyString: string;
    readonly headers: Headers;
    readonly method: HttpMethod;
    readonly url: string;
  };
}

export class PARService {
  readonly #parRepository: IPARRepository;

  constructor(parRepository: IPARRepository) {
    this.#parRepository = parRepository;
  }

  async parseAndStore(options: ParseAndStoreOptions): Promise<string> {
    const parRequestFormUrl = Object.fromEntries(new URLSearchParams(options.parRequest.bodyString));

    const clientId = parRequestFormUrl.client_id;
    const signedRequestJwt = parRequestFormUrl.request;

    if (!clientId || !signedRequestJwt) {
      throw new PostPushedAuthorizationError('client_id and request are required');
    }

    const { authorizationRequest, authorizationRequestJwt } = await parsePushedAuthorizationRequest({
      authorizationRequest: parRequestFormUrl,
      callbacks: options.callbacks,
      config: options.config,
      request: {
        headers: options.parRequest.headers,
        method: options.parRequest.method,
        url: options.parRequest.url,
      },
    });

    if (!authorizationRequestJwt) {
      throw new PostPushedAuthorizationError('signed authorization request is required');
    }

    const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
    const parSchema = getPushedAuthorizationRequestSchema(options.config);
    const storedParRequest = parSchema.parse({
      ...authorizationRequest,
      id: randomUUID(),
      request_uri: requestUri,
    });

    await this.#parRepository.insert({
      clientId,
      expiresAt: Date.now() + PAR_TTL_MS,
      requestObject: JSON.stringify(storedParRequest),
      requestUri,
    });

    return requestUri;
  }

  async getByRequestUri(requestUri: string): Promise<ParRequest> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new PostPushedAuthorizationError(`PAR entry not found for request_uri: ${requestUri}`);
    }
    return JSON.parse(entry.requestObject) as ParRequest;
  }

  async setCode(requestUri: string, code: string, codeExpiresAt: number): Promise<void> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new PostPushedAuthorizationError(`PAR entry not found for request_uri: ${requestUri}`);
    }
    const parRequest = JSON.parse(entry.requestObject) as ParRequest;
    const updated = { ...parRequest, code, code_expires_at: codeExpiresAt };
    await this.#parRepository.update(requestUri, { requestObject: JSON.stringify(updated) });
  }
}
