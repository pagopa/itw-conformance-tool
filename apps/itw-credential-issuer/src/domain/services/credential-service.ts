import { randomBytes } from 'node:crypto';

import {
  createCredentialResponse,
  parseCredentialRequest,
  verifyCredentialRequestJwtProof
} from '@pagopa/io-wallet-oid4vci';
import { ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import { decodeJwt } from 'jose';

import { createDisabilityCardCredential, DISABILITY_CARD_ID } from '../credentials/disability-card.js';
import { createPidCredential } from '../credentials/pid.js';
import { generateFakeUser } from '../faker.js';
import { applyMdocSignatureFault } from '../faults/mdoc-signature-fault.js';
import { createMdocCredential, getMdocCredentialDefinition } from '../mdoc/index.js';
import { ACCESS_TOKEN_TTL_SECONDS } from '../models/token.js';
import { type JwksRepository } from '../signer.js';
import { JwkPublicKey } from '../z-jwk.js';
import {
  CredentialRequestAuthClaimsError,
  CredentialRequestAuthProofError,
  verifyCredentialRequestAuth
} from './credential-request-auth-service.js';

import type { DisabilityCardFaultProfile } from '../credentials/disability-card.js';
import type { FakeUser } from '../faker.js';
import type { DigitalCredentialClaimsFaultMutationEvidence } from '../faults/digital-credential-claims-fault.js';
import type { DigitalCredentialSignatureFaultMutationEvidence } from '../faults/digital-credential-signature-fault.js';
import type { DigitalCredentialTrustChainFaultMutationEvidence } from '../faults/digital-credential-trust-chain-fault.js';
import type { MdocSignatureFaultMutationEvidence, MdocSignatureFaultProfile } from '../faults/mdoc-signature-fault.js';
import type { SupportedCredentialsId } from '../z-credential.js';
import type { IDeferredCredentialRepository, INonceRepository } from '@itw-conformance-tool/database';
import type { CallbackContext, JwtPayload } from '@pagopa/io-wallet-oauth2';
import type {
  CreateCredentialResponseResult,
  CredentialRequestV1_0,
  CredentialRequestV1_3,
  ParsedCredentialRequest,
  VerifyCredentialRequestJwtProofResult
} from '@pagopa/io-wallet-oid4vci';
import type { HttpMethod, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

/** Retry interval (in seconds) advertised to wallets polling `/deferred`. */
export const DEFERRED_CREDENTIAL_RETRY_INTERVAL_SECONDS = ACCESS_TOKEN_TTL_SECONDS;

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
  batchIssuanceByDeferred: boolean;
  body: string;
  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>;
  config: IoWalletSdkConfig;
  /**
   * The active WP_060 (`digital-credential-claims-invalid`) or WP_061
   * (`edc-invalid-trust-chain`) or WP_062a (`edc-invalid-signature`) fault
   * profile, if any; narrowed and passed in by the route (see
   * routes/credential.ts). Only the disability-card SD-JWT builder supports
   * these Digital Credential faults.
   */
  disabilityCardFaultProfile?: DisabilityCardFaultProfile;
  headers: Headers;
  /** The active WP_062b (`mdl-invalid-signature`) profile, if any. */
  mdocFaultProfile?: MdocSignatureFaultProfile;
  method: HttpMethod;
  trustedWalletProviderIssuers: readonly string[];
  url: string;
}

export interface CreateCredentialResult {
  /**
   * Present only when `disabilityCardFaultProfile` was provided and
   * successfully applied while creating the Digital Credential(s); lets the
   * route emit `issuer.fault.applied` only for a mutation that actually
   * happened (see `routes/credential.ts`).
   */
  disabilityCardFaultEvidence?:
    | DigitalCredentialClaimsFaultMutationEvidence
    | DigitalCredentialSignatureFaultMutationEvidence
    | DigitalCredentialTrustChainFaultMutationEvidence;
  /** Present only when `mdocFaultProfile` was provided and successfully applied. */
  mdocFaultEvidence?: MdocSignatureFaultMutationEvidence;
  /** Raw SDK result; the actual JSON body to send is `sdkResult.credentialResponse`. */
  sdkResult: CreateCredentialResponseResult;
  /** Whether the request was answered immediately (`200`) or deferred (`202`). */
  status: 'deferred' | 'immediate';
}

type ParseCredentialRequestCompatOptions = {
  callbacks?: Pick<CallbackContext, 'hash'>;
  config: IoWalletSdkConfig;
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  headers: Headers;
};

const parseCredentialRequestCompat = parseCredentialRequest as unknown as (
  options: ParseCredentialRequestCompatOptions
) => Promise<ParsedCredentialRequest>;

export class CredentialService {
  #deferredCredentialRepository: IDeferredCredentialRepository;
  #jwksRepository: JwksRepository;
  #nonceRepository: INonceRepository;

  constructor(
    jwksRepository: JwksRepository,
    nonceRepository: INonceRepository,
    deferredCredentialRepository: IDeferredCredentialRepository
  ) {
    this.#jwksRepository = jwksRepository;
    this.#nonceRepository = nonceRepository;
    this.#deferredCredentialRepository = deferredCredentialRepository;
  }

  async createCredential(options: CreateCredentialOptions): Promise<CreateCredentialResult> {
    let parsedCredentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
    try {
      parsedCredentialRequest = JSON.parse(options.body) as CredentialRequestV1_0 | CredentialRequestV1_3;
    } catch {
      throw new CreateCredentialError('Credential request body must be valid JSON');
    }

    let accessToken: string;
    let credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
    let dpopProof: string;
    let proofs: ParsedCredentialRequest['proofs'];
    try {
      ({ accessToken, credentialRequest, dpopProof, proofs } = await parseCredentialRequestCompat({
        callbacks: {
          hash: options.callbacks.hash
        },
        config: options.config,
        credentialRequest: parsedCredentialRequest,
        headers: options.headers
      }));
    } catch (error) {
      if (error instanceof CreateCredentialError) {
        throw error;
      }
      throw new CreateCredentialError('Invalid credential request payload');
    }

    let accessTokenPayload: JwtPayload & { auth_flow?: string };
    let jkt: string;
    let sub: string;
    try {
      ({ accessTokenPayload, jkt, sub } = await verifyCredentialRequestAuth({
        accessToken,
        callbacks: options.callbacks,
        dpopProof,
        headers: options.headers,
        method: options.method,
        url: options.url
      }));
    } catch (error) {
      if (error instanceof CredentialRequestAuthProofError) {
        throw new InvalidProofError(error.message);
      }
      if (error instanceof CredentialRequestAuthClaimsError) {
        throw new CreateCredentialError(error.message);
      }
      throw error;
    }

    if (!proofs || proofs.length === 0) {
      throw new CreateCredentialError('Missing proofs in credential request');
    }

    const fakeUser = generateFakeUser(sub);
    const credentialIdentifier = credentialRequest.credential_identifier as SupportedCredentialsId;

    const credentials: string[] = [];
    const noncesToConsume = new Set<string>();
    let disabilityCardFaultEvidence:
      | DigitalCredentialClaimsFaultMutationEvidence
      | DigitalCredentialSignatureFaultMutationEvidence
      | DigitalCredentialTrustChainFaultMutationEvidence
      | undefined;
    let mdocFaultEvidence: MdocSignatureFaultMutationEvidence | undefined;

    for (const proof of proofs) {
      const jwt = proof.jwt;
      if (typeof jwt !== 'string' || jwt.length === 0) {
        throw new CreateCredentialError('Missing proof JWT in credential request');
      }

      let proofPayload: ReturnType<typeof decodeJwt>;
      try {
        proofPayload = decodeJwt(jwt);
      } catch {
        throw new CreateCredentialError('Invalid proof JWT in credential request');
      }
      const { nonce } = proofPayload;
      if (typeof nonce !== 'string') {
        throw new CreateCredentialError('Missing nonce in credential request');
      }

      let proofResult: VerifyCredentialRequestJwtProofResult;
      try {
        proofResult = await this.#verifyCredentialProof(options, nonce, jwt);
      } catch (error) {
        if (error instanceof CreateCredentialError) {
          throw error;
        }
        if (error instanceof Error) {
          throw new InvalidProofError(error.message);
        }
        throw new InvalidProofError('Invalid credential proof');
      }

      noncesToConsume.add(nonce);

      const holderPublicKey = JwkPublicKey.safeParse(proofResult.header.jwk);
      if (!holderPublicKey.success) {
        throw new CreateCredentialError('Invalid parsing jwk!');
      }

      if (proofResult.header.jwk && 'd' in proofResult.header.jwk) {
        throw new CreateCredentialError('Private keys are not allowed in the proof JWT!');
      }

      const { credential, faultEvidence } = await this.#createCredentialByConfiguration(
        credentialIdentifier,
        options.baseURL,
        options.config,
        fakeUser,
        holderPublicKey.data,
        accessTokenPayload,
        options.disabilityCardFaultProfile,
        options.mdocFaultProfile
      );

      credentials.push(credential);
      if (faultEvidence) {
        if (options.mdocFaultProfile) {
          mdocFaultEvidence = faultEvidence as MdocSignatureFaultMutationEvidence;
        } else {
          disabilityCardFaultEvidence = faultEvidence as
            | DigitalCredentialClaimsFaultMutationEvidence
            | DigitalCredentialSignatureFaultMutationEvidence
            | DigitalCredentialTrustChainFaultMutationEvidence;
        }
      }
    }

    for (const nonce of noncesToConsume) {
      const consumedNonce = await this.#nonceRepository.consume(nonce);
      if (!consumedNonce) {
        throw new CreateCredentialError('Expected nonce not found');
      }
    }

    if (options.batchIssuanceByDeferred && credentials.length > 1) {
      const sdkResult = await this.#buildDeferredCredentialResponse(options, credentials, sub, jkt);
      return { disabilityCardFaultEvidence, mdocFaultEvidence, sdkResult, status: 'deferred' };
    }

    const sdkResult = await this.#buildCredentialResponse(options, credentials);
    return { disabilityCardFaultEvidence, mdocFaultEvidence, sdkResult, status: 'immediate' };
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
        trustedWalletProviderIssuers: options.trustedWalletProviderIssuers
      });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_4)) {
      return verifyCredentialRequestJwtProof({
        ...verifyOptions,
        config,
        trustedWalletProviderIssuers: options.trustedWalletProviderIssuers
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
    credentials: string[]
  ): Promise<CreateCredentialResponseResult> {
    const { config } = options;

    const [firstCredential, ...restCredentials] = credentials;
    if (!firstCredential) {
      throw new CreateCredentialError('Expected at least one credential to build the response');
    }

    // Every immediate Credential Response gets an issuer-generated
    // notification_id, mirroring the deferred flow below, so the
    // Notification Endpoint (WP_064) can be exercised without requiring a
    // batch/deferred issuance.
    const notificationId = randomBytes(32).toString('hex');

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

    throw new CreateCredentialError('Unsupported IT Wallet specs version');
  }

  async #buildDeferredCredentialResponse(
    options: CreateCredentialOptions,
    credentials: string[],
    subject: string,
    jwkThumbprint: string
  ): Promise<CreateCredentialResponseResult> {
    const { config } = options;

    const transactionId = randomBytes(32).toString('hex');

    await this.#deferredCredentialRepository.insert(transactionId, {
      credentials,
      jwkThumbprint,
      subject
    });

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      return createCredentialResponse({
        config,
        flow: { interval: DEFERRED_CREDENTIAL_RETRY_INTERVAL_SECONDS, transactionId }
      });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_4)) {
      return createCredentialResponse({
        config,
        flow: { interval: DEFERRED_CREDENTIAL_RETRY_INTERVAL_SECONDS, transactionId }
      });
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      return createCredentialResponse({
        config,
        flow: { leadTime: DEFERRED_CREDENTIAL_RETRY_INTERVAL_SECONDS, transactionId }
      });
    }

    throw new CreateCredentialError('Unsupported IT Wallet specs version');
  }

  async #createCredentialByConfiguration(
    credentialIdentifier: SupportedCredentialsId,
    baseURL: string,
    config: IoWalletSdkConfig,
    fakeUser: FakeUser,
    holderPublicKey: JwkPublicKey,
    accessTokenPayload?: JwtPayload & { auth_flow?: string },
    activeFaultProfile?: DisabilityCardFaultProfile,
    activeMdocFaultProfile?: MdocSignatureFaultProfile
  ): Promise<{
    credential: string;
    faultEvidence?:
      | DigitalCredentialClaimsFaultMutationEvidence
      | DigitalCredentialSignatureFaultMutationEvidence
      | DigitalCredentialTrustChainFaultMutationEvidence
      | MdocSignatureFaultMutationEvidence;
  }> {
    if (credentialIdentifier === 'dc_sd_jwt_PersonIdentificationData') {
      if (activeFaultProfile) {
        throw new CreateCredentialError(
          `The ${activeFaultProfile.type} fault only applies to ${DISABILITY_CARD_ID}, not ${credentialIdentifier}`
        );
      }
      if (activeMdocFaultProfile) {
        throw new CreateCredentialError(
          `The ${activeMdocFaultProfile.type} fault only applies to org.iso.18013.5.1.mDL, not ${credentialIdentifier}`
        );
      }
      const credential = await createPidCredential(
        baseURL,
        this.#jwksRepository,
        holderPublicKey,
        config,
        fakeUser,
        accessTokenPayload?.auth_flow
      );
      return { credential };
    }

    if (credentialIdentifier === 'dc_sd_jwt_EuropeanDisabilityCard') {
      if (activeMdocFaultProfile) {
        throw new CreateCredentialError(
          `The ${activeMdocFaultProfile.type} fault only applies to org.iso.18013.5.1.mDL, not ${credentialIdentifier}`
        );
      }
      return createDisabilityCardCredential(
        baseURL,
        this.#jwksRepository,
        holderPublicKey,
        config,
        fakeUser,
        activeFaultProfile
      );
    }

    if (
      credentialIdentifier === 'org.iso.18013.5.1.mDL' ||
      credentialIdentifier === 'mso_mdoc_mDL' ||
      credentialIdentifier === 'mso_mdoc_CompanyBadge' ||
      credentialIdentifier === 'mso_mdoc_PersonIdentificationData'
    ) {
      if (activeFaultProfile) {
        throw new CreateCredentialError(
          `The ${activeFaultProfile.type} fault only applies to ${DISABILITY_CARD_ID}, not ${credentialIdentifier}`
        );
      }
      if (activeMdocFaultProfile && credentialIdentifier !== 'org.iso.18013.5.1.mDL') {
        throw new CreateCredentialError(
          `The ${activeMdocFaultProfile.type} fault only applies to org.iso.18013.5.1.mDL, not ${credentialIdentifier}`
        );
      }
      const document = getMdocCredentialDefinition(credentialIdentifier, config, holderPublicKey, fakeUser);
      let credential = await createMdocCredential(document, this.#jwksRepository, holderPublicKey);

      if (activeMdocFaultProfile) {
        const mutation = applyMdocSignatureFault({ credential, profile: activeMdocFaultProfile });
        if (!mutation.ok) {
          throw new CreateCredentialError(
            `Unable to apply the mdl-invalid-signature fault to the mdoc credential: ${mutation.reason}`
          );
        }

        credential = mutation.mutation.credential;
        return { credential, faultEvidence: mutation.mutation.evidence };
      }

      return { credential };
    }

    const unsupportedIdentifier: never = credentialIdentifier;
    throw new CreateCredentialError(`Credential Identifier ${String(unsupportedIdentifier)} not found`);
  }
}
