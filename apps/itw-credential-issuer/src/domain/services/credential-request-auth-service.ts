import { Oauth2Error, extractDpopJwtFromHeaders, verifyTokenDPoP } from '@pagopa/io-wallet-oauth2';
import { decodeJwt, decodeProtectedHeader } from 'jose';

import type { CallbackContext, JwtPayload } from '@pagopa/io-wallet-oauth2';
import type { HttpMethod } from '@pagopa/io-wallet-utils';

/**
 * Structural or claims-level failure while validating the access token / DPoP
 * proof header (e.g. malformed access token, missing `cnf`/`cnf.jkt`/`sub`
 * claims, private key present in the DPoP proof header).
 */
export class CredentialRequestAuthClaimsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialRequestAuthClaimsError';
    Object.setPrototypeOf(this, CredentialRequestAuthClaimsError.prototype);
  }
}

/**
 * DPoP proof/signature verification failure (invalid DPoP proof JWT, or a
 * failed cryptographic/binding check performed by `verifyTokenDPoP`).
 */
export class CredentialRequestAuthProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialRequestAuthProofError';
    Object.setPrototypeOf(this, CredentialRequestAuthProofError.prototype);
  }
}

/**
 * Failure extracting the access token / DPoP proof JWT from request headers
 * (used by callers, such as `/deferred`, that cannot rely on
 * `parseCredentialRequest` for header extraction).
 */
export class CredentialRequestHeaderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialRequestHeaderError';
    Object.setPrototypeOf(this, CredentialRequestHeaderError.prototype);
  }
}

export interface VerifyCredentialRequestAuthOptions {
  accessToken: string;
  callbacks: Pick<CallbackContext, 'hash' | 'verifyJwt'>;
  dpopProof: string;
  headers: Headers;
  method: HttpMethod;
  url: string;
}

export interface CredentialRequestAuthResult {
  accessToken: string;
  accessTokenPayload: JwtPayload & { auth_flow?: string };
  /** JWK thumbprint bound to the access token (`cnf.jkt`). */
  jkt: string;
  /** Access token subject (`sub`). */
  sub: string;
}

/**
 * Verifies the access-token / DPoP binding shared by `POST /credential` and
 * `POST /deferred`: decodes the DPoP proof header, decodes the access token,
 * validates the `cnf`/`cnf.jkt`/`sub` claims, and cryptographically verifies
 * the DPoP proof against the request and access token.
 *
 * @throws {CredentialRequestAuthClaimsError} For structural/claims issues.
 * @throws {CredentialRequestAuthProofError} For DPoP signature/binding failures.
 */
export async function verifyCredentialRequestAuth(
  options: VerifyCredentialRequestAuthOptions
): Promise<CredentialRequestAuthResult> {
  const { accessToken, callbacks, dpopProof, headers, method, url } = options;

  let headerDpopProof: ReturnType<typeof decodeProtectedHeader>;
  try {
    headerDpopProof = decodeProtectedHeader(dpopProof);
  } catch {
    throw new CredentialRequestAuthProofError('Invalid DPoP proof');
  }
  if (!headerDpopProof.jwk || 'd' in headerDpopProof.jwk) {
    throw new CredentialRequestAuthClaimsError('Private keys are not allowed in the DPoP Proof JWT!');
  }

  let accessTokenPayload: JwtPayload & { auth_flow?: string };
  try {
    accessTokenPayload = decodeJwt<JwtPayload & { auth_flow?: string }>(accessToken);
  } catch {
    throw new CredentialRequestAuthClaimsError('Invalid access token payload');
  }
  const { cnf, sub } = accessTokenPayload;

  if (!cnf) {
    throw new CredentialRequestAuthClaimsError('Access token is missing cnf claim');
  }

  if (!cnf.jkt) {
    throw new CredentialRequestAuthClaimsError('Access token is missing cnf.jkt claim');
  }

  try {
    await verifyTokenDPoP({
      accessToken,
      callbacks,
      dpopJwt: dpopProof,
      expectedJwkThumbprint: cnf.jkt,
      request: {
        headers,
        method,
        url
      }
    });
  } catch (err) {
    if (err instanceof Oauth2Error) {
      throw new CredentialRequestAuthProofError(err.message);
    }
    throw err;
  }

  if (typeof sub !== 'string') {
    throw new CredentialRequestAuthClaimsError('Access token is missing sub claim');
  }

  return { accessToken, accessTokenPayload, jkt: cnf.jkt, sub };
}

export interface ExtractedCredentialRequestAuthHeaders {
  accessToken: string;
  dpopProof: string;
}

/**
 * Extracts the access token and DPoP proof JWT from request headers,
 * mirroring the header parsing performed internally by `parseCredentialRequest`
 * from `@pagopa/io-wallet-oid4vci`. Needed because that parser also requires
 * proof fields in the request body, which the `/deferred` request (containing
 * only `transaction_id`) does not have.
 *
 * @throws {CredentialRequestHeaderError} If the `Authorization` or `DPoP` header is missing/invalid.
 */
export function extractCredentialRequestAuthHeaders(headers: Headers): ExtractedCredentialRequestAuthHeaders {
  const authorizationHeader = headers.get('authorization')?.trim();
  if (!authorizationHeader) {
    throw new CredentialRequestHeaderError("Request is missing required 'Authorization' header with DPoP scheme");
  }

  const [scheme, token, ...rest] = authorizationHeader.split(/\s+/);
  if (rest.length > 0 || scheme?.toLowerCase() !== 'dpop' || !token) {
    throw new CredentialRequestHeaderError(
      "Request contains an invalid 'Authorization' header. Expected format: 'Authorization: DPoP <access_token>'"
    );
  }

  const extracted = extractDpopJwtFromHeaders(headers);
  if (!extracted.valid || !extracted.dpopJwt) {
    throw new CredentialRequestHeaderError("Request is missing a valid 'DPoP' header");
  }

  return { accessToken: token, dpopProof: extracted.dpopJwt };
}
