import {
  createAccessTokenResponse,
  parseAccessTokenRequest,
  verifyAccessTokenRequest,
  PkceCodeChallengeMethod
} from '@pagopa/io-wallet-oauth2';

import { ACCESS_TOKEN_TTL_SECONDS } from '../models/token.js';
import { getEntityConfigurationClaimsMetadata } from '../openid-federation/index.js';

import type { JwksRepository } from '../signer.js';
import type { ParRequest } from '../z-par.js';
import type { CallbackContext, JwtSignerJwk } from '@pagopa/io-wallet-oauth2';
import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

export class CreateAccessTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CreateAccessTokenError';
    Object.setPrototypeOf(this, CreateAccessTokenError.prototype);
  }
}

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

/**
 * Repository interface for looking up PAR entries by authorization code.
 * Implemented at the app layer using SQLite json_extract.
 */
export interface ITokenParRepository {
  getByCode(code: string): Promise<{ requestUri: string; parRequest: ParRequest } | undefined>;
  consume(requestUri: string): Promise<void>;
}

export interface CreateAccessTokenOptions {
  readonly baseURL: string;
  readonly callbacks: Pick<CallbackContext, 'generateRandom' | 'hash' | 'signJwt' | 'verifyJwt'>;
  readonly config: IoWalletSdkConfig;
  readonly tokenRequest: {
    readonly bodyString: string;
    readonly headers: Headers;
    readonly method: HttpMethod;
    readonly url: string;
  };
}

export class TokenService {
  readonly #parLookup: ITokenParRepository;
  readonly #jwksRepository: JwksRepository;

  constructor(parLookup: ITokenParRepository, jwksRepository: JwksRepository) {
    this.#parLookup = parLookup;
    this.#jwksRepository = jwksRepository;
  }

  async createAccessToken(options: CreateAccessTokenOptions): Promise<Record<string, unknown>> {
    const form = Object.fromEntries(new URLSearchParams(options.tokenRequest.bodyString));

    if (!form.code || !form.code_verifier || !form.grant_type || !form.redirect_uri) {
      throw new CreateAccessTokenError('code, code_verifier, grant_type and redirect_uri must be present');
    }

    // Parse the token request to extract DPoP, PKCE verifier, and client attestation
    const { accessTokenRequest, clientAttestation, dpop, grant, pkceCodeVerifier } = parseAccessTokenRequest({
      accessTokenRequest: form,
      request: options.tokenRequest
    });

    if (grant.grantType !== 'authorization_code') {
      throw new UnsupportedGrantTypeError(`Unsupported grant type: ${accessTokenRequest.grant_type}`);
    }

    if (!pkceCodeVerifier) {
      throw new CreateAccessTokenError('code_verifier is required');
    }

    const lookup = await this.#parLookup.getByCode(form.code);
    if (!lookup) {
      throw new InvalidGrantError('Authorization code not found or expired');
    }

    const { requestUri, parRequest } = lookup;

    if (!parRequest.code) {
      throw new InvalidGrantError('Authorization code missing in PAR request');
    }

    if (parRequest.redirect_uri !== form.redirect_uri) {
      throw new InvalidGrantError('redirect_uri mismatch');
    }

    if (!parRequest.code_challenge) {
      throw new CreateAccessTokenError('code_challenge is missing in PAR request');
    }

    if (!parRequest.code_challenge_method) {
      throw new CreateAccessTokenError('code_challenge_method is missing in PAR request');
    }

    const federationMetadata = getEntityConfigurationClaimsMetadata(
      options.baseURL,
      this.#jwksRepository,
      options.config
    );

    if (!federationMetadata?.oauth_authorization_server) {
      throw new CreateAccessTokenError('OAuth2 authorization server metadata not found');
    }

    // Verify the access token request with DPoP and PKCE validation
    const verifyAccessToken = await verifyAccessTokenRequest({
      accessTokenRequest,
      authorizationServerMetadata: federationMetadata.oauth_authorization_server,
      callbacks: options.callbacks,
      clientAttestation,
      config: options.config,
      dpop: {
        jwt: dpop.jwt
      },
      expectedCode: parRequest.code,
      grant: {
        code: form.code,
        grantType: grant.grantType
      },
      pkce: {
        codeChallenge: parRequest.code_challenge,
        codeChallengeMethod: parRequest.code_challenge_method as PkceCodeChallengeMethod,
        codeVerifier: pkceCodeVerifier
      },
      request: options.tokenRequest
    });

    // Consume the authorization code only after all validations succeed
    await this.#parLookup.consume(requestUri);

    const signer: JwtSignerJwk = {
      alg: 'ES256',
      method: 'jwk',
      publicJwk: this.#jwksRepository.getSign().public
    };

    const accessTokenResponse = await createAccessTokenResponse({
      additionalPayload: {
        authorization_details: createAuthorizationDetails(parRequest.authorization_details, federationMetadata),
        ...(parRequest.pid_auth_flow && { auth_flow: parRequest.pid_auth_flow })
      },
      audience: options.baseURL,
      authorizationServer: options.baseURL,
      callbacks: options.callbacks,
      clientId: parRequest.client_id,
      dpop: verifyAccessToken.dpop,
      expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS,
      signer,
      subject: parRequest.client_id,
      tokenType: 'DPoP'
    });

    return accessTokenResponse;
  }
}

function createAuthorizationDetails(
  authorizationDetails: ParRequest['authorization_details'],
  federationMetadata: ReturnType<typeof getEntityConfigurationClaimsMetadata>
): { credential_configuration_id: string; credential_identifiers: string[]; type: string }[] {
  if (!authorizationDetails) {
    return [];
  }

  const issuerMetadata = federationMetadata?.openid_credential_issuer;
  if (!issuerMetadata) {
    throw new CreateAccessTokenError('Credential issuer metadata not available');
  }

  return authorizationDetails.map((item) => {
    if (item.type !== 'openid_credential') {
      throw new CreateAccessTokenError(`Unsupported authorization detail type: ${item.type}`);
    }

    const credentialConfig = issuerMetadata.credential_configurations_supported[item.credential_configuration_id];

    if (!credentialConfig) {
      throw new CreateAccessTokenError(
        `No credential configuration supported for id: ${item.credential_configuration_id}`
      );
    }

    return {
      credential_configuration_id: item.credential_configuration_id,
      credential_identifiers: [item.credential_configuration_id],
      type: item.type
    };
  });
}
