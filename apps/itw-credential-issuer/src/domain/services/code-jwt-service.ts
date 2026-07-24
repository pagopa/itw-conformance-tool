import { randomUUID } from 'node:crypto';

import { SignJWT, importJWK } from 'jose';

import { AUTHORIZATION_CODE_TTL_SECONDS } from '../models/token.js';
import { getFormPostFromRedirectUriAndJwt } from '../utils/form-post-jwt.js';

import type { JwksRepository } from '../signer.js';

export interface ICodeJwtParEntry {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly requestUri: string;
  readonly state?: string;
}

export interface ICodeJwtParRepository {
  readonly get: (requestUri: string) => Promise<ICodeJwtParEntry | undefined>;
  readonly setCode: (requestUri: string, code: string, codeExpiresAt: number) => Promise<void>;
}

/**
 * The Authorization Response claims that the `authorization-response-missing-claim`
 * issuer fault (see `@itw-conformance-tool/faults`) can omit. Kept as a local
 * literal union, instead of importing the fault profile type, so this
 * service stays usable independently of the fault package.
 */
export type AuthorizationResponseClaim = 'code' | 'iss' | 'state';

export type AuthorizationResponseMutation =
  | { readonly type: 'omit-claim'; readonly claim: AuthorizationResponseClaim }
  | { readonly type: 'replace-state' }
  | { readonly type: 'replace-issuer' };

export interface CreateAuthorizationCodeJwtResult {
  readonly formPost: string;
  readonly redirectUri: string;
  /**
   * The signed Authorization Response JWT, exposed only so callers can
   * derive safe evidence (e.g. a SHA-256 hash) for `issuer.fault.applied`
   * diagnostics. Must never be logged or emitted verbatim.
   */
  readonly jwt: string;
}

export class InvalidRequestUriError extends Error {
  constructor(requestUri: string) {
    super(`request_uri not found: ${requestUri}`);
    this.name = 'InvalidRequestUriError';
    Object.setPrototypeOf(this, InvalidRequestUriError.prototype);
  }
}

export function createInvalidAuthorizationResponseState(originalState: string | undefined): string {
  return `${originalState ?? ''}.itwct-invalid-state`;
}

/**
 * Derives an `iss` value that is syntactically a valid HTTPS URL but is
 * deterministically different from the nominal Credential Issuer
 * `baseURL`, so the `authorization-response-invalid-issuer` fault mutates
 * only the semantic identity of the issuer without producing a malformed
 * claim.
 */
export function createInvalidAuthorizationResponseIssuer(baseURL: string): string {
  return `${baseURL}/itwct-invalid-issuer`;
}

export class CodeJwtService {
  private readonly baseURL: string;
  private readonly jwksRepository: JwksRepository;
  private readonly parRepository: ICodeJwtParRepository;

  constructor(opts: { baseURL: string; jwksRepository: JwksRepository; parRepository: ICodeJwtParRepository }) {
    this.baseURL = opts.baseURL;
    this.jwksRepository = opts.jwksRepository;
    this.parRepository = opts.parRepository;
  }

  async createAuthorizationCodeJwt(
    requestUri: string,
    mutation?: AuthorizationResponseMutation
  ): Promise<CreateAuthorizationCodeJwtResult> {
    const parEntry = await this.parRepository.get(requestUri);

    if (!parEntry) {
      throw new InvalidRequestUriError(requestUri);
    }

    const code = randomUUID();
    const codeExpiresAt = Math.floor(Date.now() / 1000) + AUTHORIZATION_CODE_TTL_SECONDS;

    const { private: privateSig } = this.jwksRepository.getSign();
    const importSig = await importJWK(privateSig, 'ES256');

    // Build the nominal claim set first, then remove only the requested
    // claim, so the fault mutates the same response the wallet would
    // otherwise receive instead of constructing a differently-shaped one.
    const responseClaims: Record<string, string> = {
      code,
      ...(parEntry.state ? { state: parEntry.state } : {}),
      iss: this.baseURL
    };

    if (mutation?.type === 'omit-claim') {
      delete responseClaims[mutation.claim];
    }

    if (mutation?.type === 'replace-state') {
      responseClaims.state = createInvalidAuthorizationResponseState(parEntry.state);
    }

    if (mutation?.type === 'replace-issuer') {
      responseClaims.iss = createInvalidAuthorizationResponseIssuer(this.baseURL);
    }

    const jwt = await new SignJWT(responseClaims)
      .setIssuedAt()
      .setExpirationTime(codeExpiresAt)
      .setProtectedHeader({ alg: 'ES256' })
      .sign(importSig);

    // The authorization code is always persisted with its nominal expiry,
    // even when the fault omits `code` from the response: the wallet must
    // fail because the response is malformed, not because the server never
    // recorded a redeemable code.
    await this.parRepository.setCode(requestUri, code, codeExpiresAt);

    return {
      formPost: getFormPostFromRedirectUriAndJwt(parEntry.redirectUri, jwt),
      redirectUri: parEntry.redirectUri,
      jwt
    };
  }
}
