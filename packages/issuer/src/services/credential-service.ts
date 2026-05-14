import { Oauth2Error, verifyTokenDPoP } from '@pagopa/io-wallet-oauth2';
import {
  createCredentialResponse,
  parseCredentialRequest,
  verifyCredentialRequestJwtProof
} from '@pagopa/io-wallet-oid4vci';
import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import { createDisabilityCardCredential } from '../credentials/disability-card.js';
import { createPidCredential } from '../credentials/pid.js';
import { generateFakeUser } from '../faker.js';
import { createMdocCredential, getMdocCredentialDefinition } from '../mdoc/index.js';
import { type JwksRepository } from '../signer.js';
import { JwkPublicKey } from '../z-jwk.js';

import type { FakeUser } from '../faker.js';
import type { SupportedCredentialsId } from '../z-credential.js';
import type { INonceRepository } from '@itw-conformance-tool/database';
import type { CallbackContext, JwtPayload } from '@pagopa/io-wallet-oauth2';
import type {
  CreateCredentialResponseResult,
  CredentialRequestV1_0,
  CredentialRequestV1_3,
  VerifyCredentialRequestJwtProofResult
} from '@pagopa/io-wallet-oid4vci';
import type { HttpMethod, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

const TRUSTED_WALLET_PROVIDER_ISSUERS = ['https://wallet-provider.example', 'https://wallet-provider.wct.example:3002'];

export class CreateCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CreateCredentialError';
    Object.setPrototypeOf(this, CreateCredentialError.prototype);
  }
}

export class InvalidProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidProofError';
    Object.setPrototypeOf(this, InvalidProofError.prototype);
  }
}

export interface CreateCredentialOptions {
  baseURL: string;
  body: string;
  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>;
  config: IoWalletSdkConfig;
  headers: Headers;
  method: HttpMethod;
  url: string;
}

export class CredentialService {
  #jwksRepository: JwksRepository;
  #nonceRepository: INonceRepository;

  constructor(jwksRepository: JwksRepository, nonceRepository: INonceRepository) {
    this.#jwksRepository = jwksRepository;
    this.#nonceRepository = nonceRepository;
  }

  async createCredential(options: CreateCredentialOptions): Promise<CreateCredentialResponseResult> {
    const { accessToken, credentialRequest, dpopProof, proofs } = parseCredentialRequest({
      config: options.config,
      credentialRequest: JSON.parse(options.body) as CredentialRequestV1_0 | CredentialRequestV1_3,
      headers: options.headers
    });

    const headerDpopProof = decodeProtectedHeader(dpopProof);
    if (!headerDpopProof.jwk || 'd' in headerDpopProof.jwk) {
      throw new CreateCredentialError('Private keys are not allowed in the DPoP Proof JWT!');
    }

    const { cnf, sub } = decodeJwt<JwtPayload>(accessToken);

    if (!cnf) {
      throw new CreateCredentialError('Access token is missing cnf claim');
    }

    if (!cnf.jkt) {
      throw new CreateCredentialError('Access token is missing cnf.jkt claim');
    }

    try {
      await verifyTokenDPoP({
        accessToken,
        callbacks: options.callbacks,
        dpopJwt: dpopProof,
        expectedJwkThumbprint: cnf.jkt,
        request: {
          headers: options.headers,
          method: options.method,
          url: options.url
        }
      });
    } catch (err) {
      if (err instanceof Oauth2Error) {
        throw new InvalidProofError(err.message);
      }
      throw err;
    }

    if (typeof sub !== 'string') {
      throw new CreateCredentialError('Access token is missing sub claim');
    }

    const jwt = proofs[0].jwt;

    const { nonce } = decodeJwt(jwt);
    if (typeof nonce !== 'string') {
      throw new CreateCredentialError('Missing nonce in credential request');
    }

    const storedNonce = await this.#nonceRepository.get(nonce);
    if (!storedNonce) {
      throw new CreateCredentialError('Expected nonce not found');
    }

    await this.#nonceRepository.delete(nonce);

    const proofResult = await this.#verifyCredentialProof(options, nonce, jwt);

    const holderPublicKey = JwkPublicKey.safeParse(proofResult.header.jwk);
    if (!holderPublicKey.success) {
      throw new CreateCredentialError('Invalid parsing jwk!');
    }

    if (proofResult.header.jwk && 'd' in proofResult.header.jwk) {
      throw new CreateCredentialError('Private keys are not allowed in the proof JWT!');
    }

    const fakeUser = generateFakeUser(sub);

    const credentialIdentifier = credentialRequest.credential_identifier as SupportedCredentialsId;

    const credential = await this.#createCredentialByConfiguration(
      credentialIdentifier,
      options.baseURL,
      options.config,
      fakeUser,
      holderPublicKey.data
    );

    return this.#buildCredentialResponse(options, credential);
  }

  async #verifyCredentialProof(
    options: CreateCredentialOptions,
    expectedNonce: string,
    jwt: string
  ): Promise<VerifyCredentialRequestJwtProofResult> {
    const { config } = options;
    const verifyOptions = {
      callbacks: options.callbacks,
      credentialIssuer: options.baseURL,
      expectedNonce,
      jwt
    };

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      return verifyCredentialRequestJwtProof({
        ...verifyOptions,
        config,
        trustedWalletProviderIssuers: TRUSTED_WALLET_PROVIDER_ISSUERS
      });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      return verifyCredentialRequestJwtProof({
        ...verifyOptions,
        config
      });
    }

    throw new CreateCredentialError('Unsupported IT Wallet specs version');
  }

  async #buildCredentialResponse(
    options: CreateCredentialOptions,
    credential: string
  ): Promise<CreateCredentialResponseResult> {
    const { config } = options;
    const flow: { credentials: [{ credential: string }] } = {
      credentials: [{ credential }]
    };

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      return createCredentialResponse({ config, flow });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      return createCredentialResponse({ config, flow });
    }

    throw new CreateCredentialError('Unsupported IT Wallet specs version');
  }

  async #createCredentialByConfiguration(
    credentialIdentifier: SupportedCredentialsId,
    baseURL: string,
    config: IoWalletSdkConfig,
    fakeUser: FakeUser,
    holderPublicKey: JwkPublicKey
  ): Promise<string> {
    if (credentialIdentifier === 'dc_sd_jwt_PersonIdentificationData') {
      return createPidCredential(baseURL, this.#jwksRepository, holderPublicKey, config, fakeUser);
    }

    if (credentialIdentifier === 'dc_sd_jwt_EuropeanDisabilityCard') {
      return createDisabilityCardCredential(baseURL, this.#jwksRepository, holderPublicKey, config, fakeUser);
    }

    if (
      credentialIdentifier === 'org.iso.18013.5.1.mDL' ||
      credentialIdentifier === 'mso_mdoc_mDL' ||
      credentialIdentifier === 'mso_mdoc_CompanyBadge' ||
      credentialIdentifier === 'mso_mdoc_PersonIdentificationData'
    ) {
      const document = getMdocCredentialDefinition(credentialIdentifier, config, holderPublicKey, fakeUser);
      return createMdocCredential(document, this.#jwksRepository, holderPublicKey);
    }

    const unsupportedIdentifier: never = credentialIdentifier;
    throw new CreateCredentialError(`Credential Identifier ${String(unsupportedIdentifier)} not found`);
  }
}
