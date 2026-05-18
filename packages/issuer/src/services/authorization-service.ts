import { randomBytes, randomUUID } from 'node:crypto';

import { createAuthorizationRequest, type Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';
import { ItWalletSpecsVersion, type IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { getSignJwtCallback } from '../crypto.js';
import { getFederationMetadata } from '../openid-federation/index.js';

import type { JwksRepository } from '../signer.js';
import type { ParRequest } from '../z-par.js';
import type { IPARRepository } from '@itw-conformance-tool/database';
import type { CallbackContext, TrustChain } from '@pagopa/io-wallet-oauth2';

export class AuthorizationRequestError extends Error {
  readonly statusCode: number;
  readonly redirectUri?: string;
  readonly state?: string;

  constructor(message: string, statusCode = 400, redirectUri?: string, state?: string) {
    super(message);
    this.name = 'AuthorizationRequestError';
    this.statusCode = statusCode;
    this.redirectUri = redirectUri;
    this.state = state;
    Object.setPrototypeOf(this, AuthorizationRequestError.prototype);
  }
}

export type AuthorizationResult =
  | { readonly kind: 'redirect'; readonly location: string }
  | { readonly kind: 'jwt'; readonly payload: string };

export type AuthorizeOptions = {
  readonly baseURL: string;
  readonly callbacks: Pick<CallbackContext, 'encryptJwe'>;
  readonly clientId: string;
  readonly config: IoWalletSdkConfig;
  readonly requestUri: string;
};

export class AuthorizationService {
  readonly #parRepository: IPARRepository;
  readonly #jwksRepository: JwksRepository;

  constructor(parRepository: IPARRepository, jwksRepository: JwksRepository) {
    this.#parRepository = parRepository;
    this.#jwksRepository = jwksRepository;
  }

  async authorize(options: AuthorizeOptions): Promise<AuthorizationResult> {
    const parRequest = await this.#getParRequest(options.requestUri);

    if (options.clientId !== parRequest.client_id) {
      throw new AuthorizationRequestError('client_id does not match', 400, parRequest.redirect_uri, parRequest.state);
    }

    if (!Array.isArray(parRequest.authorization_details) || parRequest.authorization_details.length === 0) {
      throw new AuthorizationRequestError(
        'missing authorization_details',
        400,
        parRequest.redirect_uri,
        parRequest.state
      );
    }

    const firstDetail = parRequest.authorization_details[0];
    if (firstDetail?.type !== 'openid_credential') {
      throw new AuthorizationRequestError(
        'unsupported credential type',
        400,
        parRequest.redirect_uri,
        parRequest.state
      );
    }

    const credentialConfigurationId = firstDetail.credential_configuration_id;

    if (credentialConfigurationId === 'dc_sd_jwt_PersonIdentificationData') {
      return await this.#authorizePid(parRequest, options);
    }

    return await this.#authorizePresentation(parRequest, options);
  }

  async #getParRequest(requestUri: string): Promise<ParRequest> {
    const entry = await this.#parRepository.get(requestUri);
    if (!entry) {
      throw new AuthorizationRequestError('request_uri not found');
    }

    return JSON.parse(entry.requestObject) as ParRequest;
  }

  async #authorizePid(parRequest: ParRequest, options: AuthorizeOptions): Promise<AuthorizationResult> {
    const code = randomUUID();
    const codeExpiresAt = Math.floor(Date.now() / 1000) + 60;
    const updatedParRequest = {
      ...parRequest,
      code,
      code_expires_at: codeExpiresAt
    };

    await this.#parRepository.update(options.requestUri, {
      requestObject: JSON.stringify(updatedParRequest)
    });

    const location = `${parRequest.redirect_uri}?code=${code}&state=${parRequest.state}&iss=${options.baseURL}`;

    return {
      kind: 'redirect',
      location
    };
  }

  async #authorizePresentation(parRequest: ParRequest, options: AuthorizeOptions): Promise<AuthorizationResult> {
    const authorizationSessionNonce = randomBytes(32).toString('hex');
    const { public: publicEnc } = this.#jwksRepository.getEncrypt();

    const requestObject: Openid4vpAuthorizationRequestPayload = {
      client_id: options.baseURL,
      client_metadata: {
        application_type: 'web',
        client_id: options.baseURL,
        client_name: 'EAA Issuer Test App',
        encrypted_response_enc_values_supported: ['A256CBC-HS512'],
        jwks: {
          keys: [publicEnc]
        },
        logo_uri: 'https://issuer.eaa.example.com/logo.png',
        request_uris: ['https://issuer.eaa.example.com/request'],
        response_uris: ['https://issuer.eaa.example.com/presentation-response'],
        vp_formats_supported: {
          'dc+sd-jwt': {
            'kb-jwt_alg_values': ['ES256'],
            'sd-jwt_alg_values': ['ES256', 'ES384']
          },
          mso_mdoc: {
            deviceauth_alg_values: [-9, -50],
            issuerauth_alg_values: [-9, -50]
          }
        }
      },
      dcql_query: getDcqlQuery(options.config),
      iss: options.baseURL,
      nonce: authorizationSessionNonce,
      response_mode: 'direct_post.jwt',
      response_type: 'vp_token',
      response_uri: `${options.baseURL}/presentation-response?request_uri=${options.requestUri}`,
      state: parRequest.state
    };

    const { private: privateSig, public: publicSig } = this.#jwksRepository.getSign();
    const federationMetadata = await getFederationMetadata({
      baseURL: options.baseURL,
      config: options.config,
      jwksRepository: this.#jwksRepository
    });

    const baseOptions = {
      authorizationRequestPayload: requestObject,
      callbacks: {
        encryptJwe: options.callbacks.encryptJwe,
        signJwt: getSignJwtCallback([privateSig])
      }
    };

    const jarOptions = {
      expiresInSeconds: 10_000
    };

    const authorizationRequest = options.config.isVersion(ItWalletSpecsVersion.V1_0)
      ? await createAuthorizationRequest({
          ...baseOptions,
          config: options.config,
          jar: {
            ...jarOptions,
            jwtSigner: {
              alg: 'ES256',
              kid: publicSig.kid,
              method: 'federation',
              trustChain: [federationMetadata] as TrustChain
            }
          }
        })
      : await createAuthorizationRequest({
          ...baseOptions,
          authorizationRequestPayload: {
            ...requestObject,
            client_id: `x509_hash:${requestObject.client_id}`
          },
          config: options.config as IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>,
          jar: {
            ...jarOptions,
            jwtSigner: {
              alg: 'ES256',
              kid: publicSig.kid,
              method: 'x5c',
              x5c: [this.#jwksRepository.iacaX509()]
            }
          }
        });

    const updatedParRequest = {
      ...parRequest,
      oid4vpRequestObject: authorizationRequest.authorizationRequestPayload
    };

    await this.#parRepository.update(options.requestUri, {
      requestObject: JSON.stringify(updatedParRequest)
    });

    return {
      kind: 'jwt',
      payload: authorizationRequest.jar.authorizationRequestJwt
    };
  }
}

function getDcqlQuery(config: IoWalletSdkConfig) {
  return {
    credentials: [
      {
        claims: [
          {
            id: 'family_name',
            path: ['family_name']
          },
          {
            id: 'given_name',
            path: ['given_name']
          },
          {
            id: config.isVersion(ItWalletSpecsVersion.V1_3) ? 'birthdate' : 'birth_date',
            path: config.isVersion(ItWalletSpecsVersion.V1_3) ? ['birthdate'] : ['birth_date']
          },
          {
            id: config.isVersion(ItWalletSpecsVersion.V1_3) ? 'place_of_birth' : 'birth_place',
            path: config.isVersion(ItWalletSpecsVersion.V1_3) ? ['place_of_birth'] : ['birth_place']
          },
          {
            id: 'nationalities',
            path: ['nationalities']
          }
        ],
        format: 'dc+sd-jwt',
        id: '0',
        meta: {
          vct_values: config.isVersion(ItWalletSpecsVersion.V1_3)
            ? ['urn:eudi:pid:it:1']
            : [
                'eu.europa.ec.eudi.pid.1',
                'urn:eu.europa.ec.eudi:pid:1',
                'https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata'
              ]
        },
        multiple: false,
        require_cryptographic_holder_binding: true
      }
    ]
  };
}
