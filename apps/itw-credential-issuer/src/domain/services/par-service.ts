import { randomUUID } from 'node:crypto';

import { decodeJwt, parsePushedAuthorizationRequest, verifyPushedAuthorizationRequest } from '@pagopa/io-wallet-oauth2';

import { PAR_TTL_MS } from '../models/par-entry.js';
import { getEntityConfigurationClaimsMetadata } from '../openid-federation/index.js';
import { getPushedAuthorizationRequestSchema } from '../z-par.js';

import type { JwksRepository } from '../signer.js';
import type { ParRequest } from '../z-par.js';
import type { IPARRepository } from '@itw-conformance-tool/database';
import type { CallbackContext, JwtSignerJwk } from '@pagopa/io-wallet-oauth2';
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
  readonly callbacks: Pick<CallbackContext, 'fetch' | 'hash' | 'verifyJwt'>;
  readonly config: IoWalletSdkConfig;
  readonly jwksRepository: JwksRepository;
  readonly parRequest: {
    readonly bodyString: string;
    readonly headers: Headers;
    readonly method: HttpMethod;
    readonly url: string;
  };
}

export interface ParseAndStoreResult {
  /**
   * The `issuer_state` claim echoed back by the wallet in the Request Object, when present.
   * It carries the conformance scenario correlation seeded in the credential offer's
   * `grants.authorization_code.issuer_state`.
   */
  readonly issuerState: string | null;
  readonly requestUri: string;
}

export class PARService {
  readonly #parRepository: IPARRepository;

  constructor(parRepository: IPARRepository) {
    this.#parRepository = parRepository;
  }

  async parseAndStore(options: ParseAndStoreOptions): Promise<ParseAndStoreResult> {
    const parRequestFormUrl = Object.fromEntries(new URLSearchParams(options.parRequest.bodyString));

    const clientId = typeof parRequestFormUrl.client_id === 'string' ? parRequestFormUrl.client_id.trim() : '';
    const signedRequestJwt = typeof parRequestFormUrl.request === 'string' ? parRequestFormUrl.request.trim() : '';

    parRequestFormUrl.client_id = clientId;
    parRequestFormUrl.request = signedRequestJwt;

    if (!clientId || !signedRequestJwt) {
      throw new PostPushedAuthorizationError('client_id and request are required');
    }

    let authorizationRequest: Awaited<ReturnType<typeof parsePushedAuthorizationRequest>>['authorizationRequest'];
    let authorizationRequestJwt: Awaited<ReturnType<typeof parsePushedAuthorizationRequest>>['authorizationRequestJwt'];
    let clientAttestation: Awaited<ReturnType<typeof parsePushedAuthorizationRequest>>['clientAttestation'];

    try {
      ({ authorizationRequest, authorizationRequestJwt, clientAttestation } = await parsePushedAuthorizationRequest({
        authorizationRequest: parRequestFormUrl,
        callbacks: options.callbacks,
        config: options.config,
        request: {
          headers: options.parRequest.headers,
          method: options.parRequest.method,
          url: options.parRequest.url
        }
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to parse pushed authorization request';
      throw new PostPushedAuthorizationError(message);
    }

    if (!authorizationRequestJwt) {
      throw new PostPushedAuthorizationError('signed authorization request is required');
    }

    if (!clientAttestation) {
      throw new PostPushedAuthorizationError('client attestation is required');
    }

    const existingParByJti = await this.#parRepository.getByJti(authorizationRequest.jti);
    if (existingParByJti) {
      throw new PostPushedAuthorizationError(
        `PAR request with jti "${authorizationRequest.jti}" has already been used`
      );
    }

    const federationMetadata = getEntityConfigurationClaimsMetadata(
      options.baseURL,
      options.jwksRepository,
      options.config
    );

    if (!federationMetadata?.oauth_authorization_server) {
      throw new PostPushedAuthorizationError('OAuth2 authorization server metadata not found');
    }

    const walletAttestationPayload = decodeJwt({
      jwt: clientAttestation.walletAttestationJwt
    }).payload;

    if (!walletAttestationPayload.cnf?.jwk) {
      throw new PostPushedAuthorizationError('wallet attestation cnf.jwk is required');
    }

    const publicJwk = walletAttestationPayload.cnf.jwk;

    const signer: JwtSignerJwk = {
      alg: 'ES256',
      method: 'jwk',
      publicJwk
    };

    await verifyPushedAuthorizationRequest({
      authorizationRequest,
      authorizationRequestJwt: {
        jwt: authorizationRequestJwt,
        signer
      },
      authorizationServerMetadata: federationMetadata.oauth_authorization_server,
      callbacks: options.callbacks,
      clientAttestation: {
        ...clientAttestation,
        ensureConfirmationKeyMatchesDpopKey: true
      },
      config: options.config,
      request: {
        headers: options.parRequest.headers,
        method: options.parRequest.method,
        url: options.parRequest.url
      }
    });

    const requestUri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
    const parSchema = getPushedAuthorizationRequestSchema(options.config);
    const storedParRequest = parSchema.parse({
      ...authorizationRequest,
      id: randomUUID(),
      request_uri: requestUri
    });

    await this.#parRepository.insert({
      clientId: storedParRequest.client_id,
      expiresAt: Date.now() + PAR_TTL_MS,
      requestObject: JSON.stringify(storedParRequest),
      requestUri
    });

    return { requestUri, issuerState: authorizationRequest.issuer_state ?? null };
  }

  async getByRequestUri(requestUri: string): Promise<ParRequest> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new PostPushedAuthorizationError(`PAR entry not found for request_uri: ${requestUri}`);
    }
    return JSON.parse(entry.requestObject) as ParRequest;
  }

  async setCode(requestUri: string, code: string, codeExpiresAtSeconds: number): Promise<void> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new PostPushedAuthorizationError(`PAR entry not found for request_uri: ${requestUri}`);
    }
    const parRequest = JSON.parse(entry.requestObject) as ParRequest;
    const updated = { ...parRequest, code, code_expires_at: codeExpiresAtSeconds };
    await this.#parRepository.update(requestUri, { requestObject: JSON.stringify(updated) });
  }
}
