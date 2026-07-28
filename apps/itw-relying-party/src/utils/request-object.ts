import { decodeJwt, decodeProtectedHeader, generateKeyPair, importJWK, SignJWT } from 'jose';

import type { RequestObjectOmittedParameter } from '@itw-conformance-tool/faults';
import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const REQUEST_OBJECT_SIGNING_ALG = 'ES256';

/**
 * A syntactically valid client identifier that is neither the engagement
 * `client_id` nor the `sub` of the Relying Party Entity Configuration:
 * `.invalid` is reserved by RFC 2606, so it can never resolve to a real
 * federation participant. Used only by the `request-object-invalid-client-id`
 * fault (WP_086).
 */
export const MISMATCHED_REQUEST_OBJECT_ISSUER = 'https://wp-086-client-id-mismatch.itw-conformance-tool.invalid';

/** Request Object mutation requested by an active Relying Party fault profile. */
export type RequestObjectMutation =
  | { type: 'invalid-signature' }
  | { type: 'mismatched-issuer' }
  | { type: 'omit-parameter'; parameter: RequestObjectOmittedParameter };

export interface ReissueRequestObjectOptions {
  /** The nominal, stored Request Object JWT whose header and claims are reused. */
  jwt: string;
  mutation?: RequestObjectMutation;
  /** The Relying Party signing key the nominal Request Object was signed with. */
  signingPrivateJwk: Jwk;
  /** `wallet_nonce` to echo back, as sent by the wallet on a `request_uri_method=post` retrieval. */
  walletNonce?: string;
}

/**
 * Rebuilds the stored Request Object so it can carry retrieval-time data (the
 * wallet's `wallet_nonce`) and/or an active fault mutation, then re-signs it
 * with the same protected header the nominal Request Object used.
 *
 * The header is reused verbatim — including `kid` and `x5c` — so a wallet
 * resolves the verification key exactly as it would for a nominal Request
 * Object. Only `invalid-signature` changes the signing key, and it changes
 * nothing else: the resulting JWT is well formed and its claims are nominal,
 * but no key a wallet can resolve verifies it.
 */
export async function reissueRequestObjectJwt(options: ReissueRequestObjectOptions): Promise<string> {
  // `b64` (RFC 7797 unencoded payload) never appears in a JAR and is typed more
  // narrowly on the signing side than on the decoding side, so it is dropped
  // rather than carried over.
  const { b64, ...header } = decodeProtectedHeader(options.jwt);
  void b64;
  const payload: Record<string, unknown> = { ...decodeJwt(options.jwt) };

  if (options.walletNonce !== undefined) {
    payload.wallet_nonce = options.walletNonce;
  }

  if (options.mutation?.type === 'mismatched-issuer') {
    payload.iss = MISMATCHED_REQUEST_OBJECT_ISSUER;
  }

  if (options.mutation?.type === 'omit-parameter') {
    delete payload[options.mutation.parameter];
  }

  const alg = header.alg ?? REQUEST_OBJECT_SIGNING_ALG;
  const signingKey =
    options.mutation?.type === 'invalid-signature'
      ? (await generateKeyPair(alg)).privateKey
      : await importJWK(options.signingPrivateJwk as JWK, alg);

  return new SignJWT(payload).setProtectedHeader({ ...header, alg }).sign(signingKey);
}
