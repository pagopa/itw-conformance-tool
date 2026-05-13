import type {
  ItWalletCredentialIssuerMetadata,
  ItWalletCredentialIssuerMetadataV1_3
} from '@pagopa/io-wallet-oid-federation';

import { JwksRepository } from '@/domain/signer';
import {
  CallbackContext,
  PkceCodeChallengeMethod,
  createAccessTokenResponse,
  parseAccessTokenRequest,
  verifyAccessTokenRequest
} from '@pagopa/io-wallet-oauth2';
import { HttpMethod, IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { getEntityConfigurationClaimsMetadata } from './openid-federation';
import { ParRequestRepository } from './par';
import { ParRequest } from './z-par';

export class CreateAccessTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CreateAccessTokenError';

    Object.setPrototypeOf(this, CreateAccessTokenError.prototype);
  }
}

/**
 * Error thrown when the provided authorization grant (e.g., authorization code)
 * is invalid, expired, revoked, does not match the redirection URI used in
 * the authorization request, or has already been used.
 * * Maps to the HTTP 400 `invalid_grant` error response.
 */
export class InvalidGrantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidGrantError';

    Object.setPrototypeOf(this, InvalidGrantError.prototype);
  }
}

export class UnsupportedGrantTypeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedGrantTypeError';

    Object.setPrototypeOf(this, UnsupportedGrantTypeError.prototype);
  }
}

export interface CreateAccessTokenOptions {
  /* * The body of the request, as a string. */
  baseURL: string;

  /* The Oauth2AuthorizationServer instance to use for creating the access token */
  callbacks: Pick<CallbackContext, 'generateRandom' | 'hash' | 'signJwt' | 'verifyJwt'>;

  config: IoWalletSdkConfig;

  /* The JwksRepository used to sign the access token */
  jwksRepository: JwksRepository;

  /* Repository for storing Pushed Authorization Requests. */
  parRequestRepository: ParRequestRepository;

  /* The HTTP request object containing headers and other request details */
  tokenRequest: {
    bodyString: string;
    headers: Headers;
    method: HttpMethod;
    url: string;
  };
}

/**
 * Processes a token request and generates an Access Token response.
 * * This implementation enforces:
 * - Single-use authorization codes (prevents replay attacks).
 * - Time-to-live (TTL) validation for authorization codes.
 * - Proper mapping of database exceptions to OAuth2 `invalid_grant` errors.
 * * @param {CreateAccessTokenOptions} options - Configuration, repositories and request details.
 * @throws {InvalidGrantError} If the code is missing, expired, already used, or if the
 * `redirect_uri` in the token request does not match the one registered in the PAR request.
 * @throws {CreateAccessTokenError} For configuration or internal protocol errors.
 */
export const createAccessToken = async (options: CreateAccessTokenOptions) => {
  const tokenRequestFormUrl = Object.fromEntries(new URLSearchParams(options.tokenRequest.bodyString));

  if (
    !tokenRequestFormUrl.code ||
    !tokenRequestFormUrl.code_verifier ||
    !tokenRequestFormUrl.grant_type ||
    !tokenRequestFormUrl.redirect_uri
  ) {
    throw new CreateAccessTokenError(`code, code_verifier, grant_type and redirect_uri must be present!`);
  }

  const { accessTokenRequest, clientAttestation, dpop, grant, pkceCodeVerifier } = parseAccessTokenRequest({
    accessTokenRequest: tokenRequestFormUrl,
    request: options.tokenRequest
  });

  const parRequest = await options.parRequestRepository
    .get({ code: tokenRequestFormUrl.code })
    .catch((err: unknown) => {
      throw new InvalidGrantError(err instanceof Error ? err.message : String(err));
    });

  if (parRequest.redirect_uri !== tokenRequestFormUrl.redirect_uri) {
    throw new InvalidGrantError('redirect_uri mismatch');
  }

  if (grant.grantType !== 'authorization_code') {
    throw new UnsupportedGrantTypeError(`Unsupported grant type: ${accessTokenRequest.grant_type}`);
  }

  const federationMetadata = getEntityConfigurationClaimsMetadata(
    options.baseURL,
    options.jwksRepository,
    options.config
  );

  const verifyAccessToken = await verifyAccessTokenRequest({
    accessTokenRequest: accessTokenRequest,
    authorizationServerMetadata: federationMetadata.oauth_authorization_server,
    callbacks: options.callbacks,
    clientAttestation,
    config: options.config,
    dpop: {
      jwt: dpop.jwt
    },
    expectedCode: parRequest.code,
    grant: {
      code: tokenRequestFormUrl.code,
      grantType: grant.grantType
    },
    pkce: {
      codeChallenge: parRequest.code_challenge,
      codeChallengeMethod: parRequest.code_challenge_method as PkceCodeChallengeMethod,
      codeVerifier: pkceCodeVerifier
    },
    request: options.tokenRequest
  });

  // Consume the authorization code only after all validations succeed,
  // preventing DoS via mismatched redirect_uri burning a valid code.
  await options.parRequestRepository.consumeByCode(tokenRequestFormUrl.code);

  const accessTokenResponse = await createAccessTokenResponse({
    additionalPayload: {
      authorization_details: createAuthorizationDetails(
        parRequest.authorization_details,
        federationMetadata.openid_credential_issuer
      )
    },
    audience: options.baseURL,
    authorizationServer: options.baseURL,
    callbacks: options.callbacks,
    clientId: parRequest.client_id,
    dpop: verifyAccessToken.dpop,
    expiresInSeconds: 300,
    signer: {
      alg: 'ES256',
      method: 'jwk',
      publicJwk: options.jwksRepository.getSign().public
    },
    subject: parRequest.client_id,
    tokenType: 'DPoP'
  });

  return accessTokenResponse;
};

/**
 * Creates an array of authorization details by mapping over the provided authorization details
 * and enriching each item with credential identifiers based on issuer metadata.
 *
 * @param {ParRequest["authorization_details"]} authorizationDetails - The list of requested authorization details.
 * @param {CredentialIssuerMetadata} issuerMetadata - Metadata that includes supported credential configurations.
 *
 * @returns {( { credential_identifiers: string[] }[] & ParRequest["authorization_details"] )}
 * Returns an array of authorization detail objects, each extended with a list of credential identifiers.
 *
 * @throws {CreateAccessTokenError} Throws an error if the credential configuration ID does not exist in issuer metadata.
 */
const createAuthorizationDetails = (
  authorizationDetails: ParRequest['authorization_details'],
  issuerMetadata: ItWalletCredentialIssuerMetadata | ItWalletCredentialIssuerMetadataV1_3
): { credential_identifiers: string[] }[] & ParRequest['authorization_details'] =>
  authorizationDetails.map((item) => {
    if (item.type !== 'openid_credential') {
      throw new CreateAccessTokenError(`Unsupported authorization detail type: ${item.type}`);
    }

    const credentialConfig = issuerMetadata.credential_configurations_supported[item.credential_configuration_id];

    if (!credentialConfig) {
      throw new CreateAccessTokenError(
        `No Credential configuration supported for id: ${item.credential_configuration_id}`
      );
    }

    return {
      credential_configuration_id: item.credential_configuration_id,
      credential_identifiers: [item.credential_configuration_id],
      type: item.type
    };
  });
