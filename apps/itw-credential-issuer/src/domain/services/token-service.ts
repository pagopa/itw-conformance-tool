import { randomUUID } from 'node:crypto';

import {
  createAccessTokenResponse,
  decodeJwt,
  parseAccessTokenRequest,
  verifyAccessTokenRequest,
  verifyClientAttestation,
  verifyTokenDPoP,
  Oauth2Error,
  PkceCodeChallengeMethod,
  zRefreshTokenProfileJwtHeader,
  zRefreshTokenProfileJwtPayload
} from '@pagopa/io-wallet-oauth2';

import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS } from '../models/token.js';
import { getEntityConfigurationClaimsMetadata } from '../openid-federation/index.js';

import type { JwksRepository } from '../signer.js';
import type { ParRequest } from '../z-par.js';
import type { IRefreshTokenRepository, RefreshTokenEntry } from '@itw-conformance-tool/database';
import type {
  AccessTokenRequest,
  CallbackContext,
  ClientAttestationOptions,
  JwtSignerJwk,
  ParsedAccessTokenAuthorizationCodeRequestGrant,
  ParsedAccessTokenRefreshTokenRequestGrant
} from '@pagopa/io-wallet-oauth2';
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

export class InvalidDpopProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidDpopProofError';
    Object.setPrototypeOf(this, InvalidDpopProofError.prototype);
  }
}

export class InvalidClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidClientError';
    Object.setPrototypeOf(this, InvalidClientError.prototype);
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

export interface CreateAccessTokenResult {
  /**
   * The `issuer_state` claim carried by the PAR request associated with this
   * token exchange, when present. Mirrors `ParseAndStoreResult.issuerState` in
   * `par-service.ts` and is used to correlate the `issuer.token.requested`
   * observed event with the same conformance scenario run as `issuer.par.requested`.
   * `null` for the refresh_token grant, which has no associated PAR request.
   */
  readonly issuerState: string | null;
  readonly response: Record<string, unknown>;
}

type FederationMetadata = ReturnType<typeof getEntityConfigurationClaimsMetadata>;
type AuthorizationServerMetadata = NonNullable<NonNullable<FederationMetadata>['oauth_authorization_server']>;

export class TokenService {
  readonly #parLookup: ITokenParRepository;
  readonly #jwksRepository: JwksRepository;
  readonly #refreshTokenRepository: IRefreshTokenRepository;

  constructor(
    parLookup: ITokenParRepository,
    jwksRepository: JwksRepository,
    refreshTokenRepository: IRefreshTokenRepository
  ) {
    this.#parLookup = parLookup;
    this.#jwksRepository = jwksRepository;
    this.#refreshTokenRepository = refreshTokenRepository;
  }

  async createAccessToken(options: CreateAccessTokenOptions): Promise<CreateAccessTokenResult> {
    const form = Object.fromEntries(new URLSearchParams(options.tokenRequest.bodyString));

    if (!form.grant_type) {
      throw new CreateAccessTokenError('grant_type must be present');
    }

    if (form.grant_type !== 'authorization_code' && form.grant_type !== 'refresh_token') {
      throw new UnsupportedGrantTypeError(`Unsupported grant type: ${form.grant_type}`);
    }

    // Parse the token request to extract DPoP, PKCE verifier, and client attestation.
    const { accessTokenRequest, clientAttestation, dpop, grant, pkceCodeVerifier } = parseAccessTokenRequest({
      accessTokenRequest: form,
      request: options.tokenRequest
    });

    const federationMetadata = getEntityConfigurationClaimsMetadata(
      options.baseURL,
      this.#jwksRepository,
      options.config
    );

    if (!federationMetadata?.oauth_authorization_server) {
      throw new CreateAccessTokenError('OAuth2 authorization server metadata not found');
    }

    const authorizationServerMetadata = federationMetadata.oauth_authorization_server;

    if (grant.grantType === 'authorization_code') {
      // The parsed/validated request silently strips fields belonging to the other
      // grant (Zod `$strip` mode), so parameters that only make sense for the
      // refresh_token grant must be rejected explicitly here.
      if (form.refresh_token !== undefined) {
        throw new CreateAccessTokenError('refresh_token must not be present for the authorization_code grant');
      }

      if (!pkceCodeVerifier) {
        throw new CreateAccessTokenError('code_verifier is required');
      }

      return this.#exchangeAuthorizationCode({
        accessTokenRequest,
        authorizationServerMetadata,
        clientAttestation,
        dpop,
        federationMetadata,
        form,
        grant,
        options,
        pkceCodeVerifier
      });
    }

    if (form.code !== undefined || form.code_verifier !== undefined || form.redirect_uri !== undefined) {
      throw new CreateAccessTokenError(
        'code, code_verifier and redirect_uri must not be present for the refresh_token grant'
      );
    }

    return this.#exchangeRefreshToken({
      accessTokenRequest,
      authorizationServerMetadata,
      clientAttestation,
      dpop,
      grant,
      options
    });
  }

  async #exchangeAuthorizationCode(input: {
    accessTokenRequest: AccessTokenRequest;
    authorizationServerMetadata: AuthorizationServerMetadata;
    clientAttestation: { clientAttestationPopJwt: string; walletAttestationJwt: string };
    dpop: { jwt: string };
    federationMetadata: FederationMetadata;
    form: Record<string, string>;
    grant: ParsedAccessTokenAuthorizationCodeRequestGrant;
    options: CreateAccessTokenOptions;
    pkceCodeVerifier: string;
  }): Promise<CreateAccessTokenResult> {
    const {
      accessTokenRequest,
      authorizationServerMetadata,
      clientAttestation,
      dpop,
      federationMetadata,
      form,
      grant,
      options,
      pkceCodeVerifier
    } = input;

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

    // Verify the access token request with DPoP and PKCE validation.
    const verifyAccessToken = await verifyAccessTokenRequest({
      accessTokenRequest,
      authorizationServerMetadata,
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

    // Consume the authorization code only after all validations succeed.
    await this.#parLookup.consume(requestUri);

    const signer: JwtSignerJwk = {
      alg: 'ES256',
      method: 'jwk',
      publicJwk: this.#jwksRepository.getSign().public
    };

    const authorizationDetails = createAuthorizationDetails(parRequest.authorization_details, federationMetadata);

    const accessTokenResponse = await createAccessTokenResponse({
      additionalPayload: buildAdditionalPayload(authorizationDetails, parRequest.pid_auth_flow),
      audience: options.baseURL,
      authorizationServer: options.baseURL,
      callbacks: options.callbacks,
      clientId: parRequest.client_id,
      dpop: verifyAccessToken.dpop,
      expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenExpiresInSeconds: REFRESH_TOKEN_TTL_SECONDS,
      scope: parRequest.scope,
      signer,
      subject: parRequest.client_id,
      tokenType: 'DPoP'
    });

    if (accessTokenResponse.refresh_token) {
      await this.#persistIssuedRefreshToken({
        authFlow: parRequest.pid_auth_flow,
        authorizationDetails,
        clientId: parRequest.client_id,
        dpopJkt: verifyAccessToken.dpop.jwkThumbprint,
        refreshTokenJwt: accessTokenResponse.refresh_token,
        scope: parRequest.scope,
        subject: parRequest.client_id
      });
    }

    return { issuerState: parRequest.issuer_state ?? null, response: accessTokenResponse };
  }

  async #exchangeRefreshToken(input: {
    accessTokenRequest: AccessTokenRequest;
    authorizationServerMetadata: AuthorizationServerMetadata;
    clientAttestation: ClientAttestationOptions;
    dpop: { jwt: string };
    grant: ParsedAccessTokenRefreshTokenRequestGrant;
    options: CreateAccessTokenOptions;
  }): Promise<CreateAccessTokenResult> {
    const { accessTokenRequest, authorizationServerMetadata, clientAttestation, dpop, grant, options } = input;
    const requestedScope = 'scope' in accessTokenRequest ? accessTokenRequest.scope : undefined;

    // Structural/schema validation only; the signature is verified separately below.
    let decoded: ReturnType<
      typeof decodeJwt<typeof zRefreshTokenProfileJwtHeader, typeof zRefreshTokenProfileJwtPayload>
    >;
    try {
      decoded = decodeJwt({
        headerSchema: zRefreshTokenProfileJwtHeader,
        jwt: grant.refreshToken,
        payloadSchema: zRefreshTokenProfileJwtPayload
      });
    } catch {
      throw new InvalidGrantError('Malformed refresh token');
    }
    const { header, payload } = decoded;

    const signKey = this.#jwksRepository.getSign();
    if (header.kid !== signKey.public.kid) {
      throw new InvalidGrantError('Refresh token was not signed by a known issuer key');
    }

    const verification = await options.callbacks.verifyJwt(
      { alg: header.alg, method: 'jwk', publicJwk: signKey.public },
      { compact: grant.refreshToken, header, payload }
    );
    if (!verification.verified) {
      throw new InvalidGrantError('Refresh token signature verification failed');
    }

    if (payload.iss !== options.baseURL || payload.aud !== options.baseURL) {
      throw new InvalidGrantError('Refresh token iss/aud mismatch');
    }

    // `callbacks.verifyJwt` applies a lenient clock tolerance (see domain/crypto.ts),
    // so exact temporal checks against the refresh token profile are enforced here
    // without any additional skew.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSeconds) {
      throw new InvalidGrantError('Refresh token has expired');
    }
    // Disabled to enalbe testing of refresh tokens
    // if (payload.nbf > nowSeconds) {
    //   throw new InvalidGrantError('Refresh token is not yet valid');
    // }
    if (payload.iat > nowSeconds) {
      throw new InvalidGrantError('Refresh token was issued in the future');
    }

    if (!UUID_V4_PATTERN.test(payload.jti)) {
      throw new InvalidGrantError('Refresh token jti is not a valid UUIDv4');
    }
    if (!payload.client_id.trim() || !payload.sub.trim()) {
      throw new InvalidGrantError('Refresh token client_id/sub must not be empty');
    }

    let dpopVerification: Awaited<ReturnType<typeof verifyTokenDPoP>>;
    try {
      dpopVerification = await verifyTokenDPoP({
        callbacks: options.callbacks,
        dpopJwt: dpop.jwt,
        expectedJwkThumbprint: payload.cnf.jkt,
        request: options.tokenRequest
      });
    } catch (error) {
      if (error instanceof Oauth2Error) {
        throw new InvalidDpopProofError(error.message);
      }
      throw error;
    }

    try {
      await verifyClientAttestation({
        authorizationServerMetadata,
        callbacks: options.callbacks,
        clientAttestation,
        config: options.config,
        dpopJwkThumbprint: payload.cnf.jkt,
        requestClientId: payload.client_id
      });
    } catch (error) {
      if (error instanceof Oauth2Error) {
        throw new InvalidClientError(error.message);
      }
      throw error;
    }

    // Atomically claim the presented refresh token exactly once: `rotate` marks
    // `payload.jti` as consumed and returns its stored authorization context, or
    // `undefined` if it was unknown, expired, or already used. A throwaway
    // placeholder entry (keyed by a locally-generated random jti that no other
    // request can guess) takes its place until the real new entry is known, see
    // the finalizing `rotate` call below.
    const claimJti = randomUUID();
    const claimedContext = await this.#refreshTokenRepository.rotate(payload.jti, {
      authorizationDetails: null,
      clientId: payload.client_id,
      dpopJkt: payload.cnf.jkt,
      expiresAt: Date.now() + REFRESH_TOKEN_CLAIM_TTL_MS,
      jti: claimJti,
      subject: payload.sub
    });

    if (!claimedContext) {
      throw new InvalidGrantError('Refresh token not found, expired, or already used');
    }

    if (
      claimedContext.clientId !== payload.client_id ||
      claimedContext.subject !== payload.sub ||
      claimedContext.dpopJkt !== payload.cnf.jkt
    ) {
      throw new InvalidGrantError('Refresh token context does not match its client, subject, or DPoP key');
    }

    const scope = resolveRefreshScope(claimedContext.scope, requestedScope);

    const signer: JwtSignerJwk = {
      alg: 'ES256',
      method: 'jwk',
      publicJwk: signKey.public
    };

    const accessTokenResponse = await createAccessTokenResponse({
      additionalPayload: buildAdditionalPayload(claimedContext.authorizationDetails, claimedContext.authFlow),
      audience: options.baseURL,
      authorizationServer: options.baseURL,
      callbacks: options.callbacks,
      clientId: payload.client_id,
      dpop: { jwk: dpopVerification.header.jwk },
      expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenExpiresInSeconds: REFRESH_TOKEN_TTL_SECONDS,
      scope,
      signer,
      subject: payload.sub,
      tokenType: 'DPoP'
    });

    if (!accessTokenResponse.refresh_token) {
      throw new CreateAccessTokenError('Refresh token issuance failed');
    }

    const newRefreshToken = decodeIssuedRefreshToken(accessTokenResponse.refresh_token);

    // Finalize the rotation: swap the throwaway placeholder for the real new
    // entry now that its jti/expiry are known. This always succeeds because
    // `claimJti` was generated locally and cannot be known to any other
    // concurrent request.
    await this.#refreshTokenRepository.rotate(claimJti, {
      authFlow: claimedContext.authFlow,
      authorizationDetails: claimedContext.authorizationDetails,
      clientId: payload.client_id,
      dpopJkt: payload.cnf.jkt,
      expiresAt: newRefreshToken.exp * 1000,
      jti: newRefreshToken.jti,
      scope,
      subject: payload.sub
    });

    return { issuerState: null, response: accessTokenResponse };
  }

  async #persistIssuedRefreshToken(input: {
    authFlow?: string;
    authorizationDetails: unknown;
    clientId: string;
    dpopJkt: string;
    refreshTokenJwt: string;
    scope?: string;
    subject: string;
  }): Promise<void> {
    const { jti, exp } = decodeIssuedRefreshToken(input.refreshTokenJwt);

    const entry: RefreshTokenEntry = {
      authFlow: input.authFlow,
      authorizationDetails: input.authorizationDetails,
      clientId: input.clientId,
      dpopJkt: input.dpopJkt,
      expiresAt: exp * 1000,
      jti,
      scope: input.scope,
      subject: input.subject
    };

    await this.#refreshTokenRepository.insert(entry);
  }
}

const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Short-lived placeholder window for the "claim" half of the double-rotate
// pattern: it only needs to outlive the time it takes to build the new token
// response before being finalized, and self-expires (swept by the repository)
// if the process crashes in between.
const REFRESH_TOKEN_CLAIM_TTL_MS = 60_000;

function buildAdditionalPayload(authorizationDetails: unknown, authFlow?: string): Record<string, unknown> {
  return {
    authorization_details: authorizationDetails,
    ...(authFlow && { auth_flow: authFlow })
  };
}

/**
 * Decodes and structurally validates a refresh token JWT that this issuer just
 * minted via `createAccessTokenResponse`. Failures here indicate a bug in the
 * SDK/issuer rather than an untrusted client input.
 */
function decodeIssuedRefreshToken(refreshTokenJwt: string): { exp: number; jti: string } {
  try {
    const { payload } = decodeJwt({
      headerSchema: zRefreshTokenProfileJwtHeader,
      jwt: refreshTokenJwt,
      payloadSchema: zRefreshTokenProfileJwtPayload
    });
    return { exp: payload.exp, jti: payload.jti };
  } catch {
    throw new CreateAccessTokenError('Issued refresh token failed profile validation');
  }
}

/**
 * Resolves the scope for a refreshed access token: reuses the original scope
 * when the client omits `scope`, otherwise requires the requested scope to be
 * a subset of (or equal to) the originally granted one (RFC 6749 §6).
 */
function resolveRefreshScope(
  originalScope: string | undefined,
  requestedScope: string | undefined
): string | undefined {
  if (requestedScope === undefined) {
    return originalScope;
  }

  const originalValues = new Set((originalScope ?? '').split(/\s+/).filter(Boolean));
  const requestedValues = requestedScope.split(/\s+/).filter(Boolean);

  if (!requestedValues.every((value) => originalValues.has(value))) {
    throw new InvalidGrantError('Requested scope exceeds the scope originally granted');
  }

  return requestedScope;
}

function createAuthorizationDetails(
  authorizationDetails: ParRequest['authorization_details'],
  federationMetadata: FederationMetadata
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
