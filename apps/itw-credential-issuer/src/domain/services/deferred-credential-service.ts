import { createCredentialResponse } from '@pagopa/io-wallet-oid4vci';
import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

import {
  CredentialRequestAuthClaimsError,
  CredentialRequestAuthProofError,
  CredentialRequestHeaderError,
  extractCredentialRequestAuthHeaders,
  verifyCredentialRequestAuth
} from './credential-request-auth-service.js';

import type { IDeferredCredentialRepository } from '@itw-conformance-tool/database';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';
import type { CreateCredentialResponseResult } from '@pagopa/io-wallet-oid4vci';
import type { HttpMethod, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

/**
 * Raised for missing, malformed, unknown, mismatched, or already-consumed
 * `transaction_id` values. Always maps to the same protocol error response so
 * callers cannot distinguish which condition occurred.
 */
export class InvalidTransactionIdError extends Error {
  constructor(message = 'Invalid, unknown, or already-consumed transaction ID') {
    super(message);
    this.name = 'InvalidTransactionIdError';
    Object.setPrototypeOf(this, InvalidTransactionIdError.prototype);
  }
}

/** Raised for missing/invalid access-token or DPoP proof authorization. */
export class DeferredCredentialAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeferredCredentialAuthError';
    Object.setPrototypeOf(this, DeferredCredentialAuthError.prototype);
  }
}

export interface RetrieveDeferredCredentialOptions {
  body: string;
  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>;
  config: IoWalletSdkConfig;
  headers: Headers;
  method: HttpMethod;
  url: string;
}

export class DeferredCredentialService {
  #deferredCredentialRepository: IDeferredCredentialRepository;

  constructor(deferredCredentialRepository: IDeferredCredentialRepository) {
    this.#deferredCredentialRepository = deferredCredentialRepository;
  }

  async retrieveDeferredCredential(
    options: RetrieveDeferredCredentialOptions
  ): Promise<CreateCredentialResponseResult> {
    const transactionId = this.#parseTransactionId(options.body);

    let accessToken: string;
    let dpopProof: string;
    try {
      ({ accessToken, dpopProof } = extractCredentialRequestAuthHeaders(options.headers));
    } catch (error) {
      if (error instanceof CredentialRequestHeaderError) {
        throw new DeferredCredentialAuthError(error.message);
      }
      throw error;
    }

    let jkt: string;
    let sub: string;
    try {
      ({ jkt, sub } = await verifyCredentialRequestAuth({
        accessToken,
        callbacks: options.callbacks,
        dpopProof,
        headers: options.headers,
        method: options.method,
        url: options.url
      }));
    } catch (error) {
      if (error instanceof CredentialRequestAuthProofError || error instanceof CredentialRequestAuthClaimsError) {
        throw new DeferredCredentialAuthError(error.message);
      }
      throw error;
    }

    const record = await this.#deferredCredentialRepository.consume(transactionId, sub, jkt);
    if (!record) {
      throw new InvalidTransactionIdError();
    }

    return this.#buildImmediateResponse(options.config, record.credentials, record.notificationId);
  }

  #parseTransactionId(body: string): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new InvalidTransactionIdError('Deferred credential request body must be valid JSON');
    }

    const transactionId = (parsed as { transaction_id?: unknown } | null)?.transaction_id;
    if (typeof transactionId !== 'string' || transactionId.length === 0) {
      throw new InvalidTransactionIdError('Deferred credential request is missing a valid transaction_id');
    }

    return transactionId;
  }

  async #buildImmediateResponse(
    config: IoWalletSdkConfig,
    credentials: string[],
    notificationId: string
  ): Promise<CreateCredentialResponseResult> {
    const [firstCredential, ...restCredentials] = credentials;
    if (!firstCredential) {
      throw new InvalidTransactionIdError('Stored deferred credential batch is empty');
    }

    const flow = {
      credentials: [{ credential: firstCredential }, ...restCredentials.map((credential) => ({ credential }))] as [
        { credential: string },
        ...{ credential: string }[]
      ],
      notificationId
    };

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      return createCredentialResponse({ config, flow });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_4)) {
      return createCredentialResponse({ config, flow });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      return createCredentialResponse({ config, flow });
    }

    throw new Error('Unsupported IT Wallet specs version');
  }
}
