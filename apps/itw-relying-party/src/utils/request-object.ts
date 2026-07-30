import { extractClientIdPrefix } from '@pagopa/io-wallet-oid4vp';
import { decodeJwt, decodeProtectedHeader, generateKeyPair, importJWK, SignJWT } from 'jose';

import type { RequestObjectOmittedParameter } from '@itw-conformance-tool/faults';
import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const REQUEST_OBJECT_SIGNING_ALG = 'ES256';

/**
 * The OpenID Federation Client Identifier Prefix. A `client_id` carrying it tells
 * the wallet to resolve the Relying Party — and its signing key — through the
 * federation Trust Chain, rather than from the `x5c` certificate chain the
 * nominal `x509_hash` prefix points at.
 */
const OPENID_FEDERATION_CLIENT_ID_PREFIX = 'openid_federation';

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
  | { type: 'federation-key' }
  | { type: 'invalid-signature' }
  | { type: 'mismatched-issuer' }
  | { type: 'omit-parameter'; parameter: RequestObjectOmittedParameter };

/** What the `federation-key` mutation (WP_084) changed, for the fault evidence. */
export interface FederationKeyMutationResult {
  clientId: string;
  /** `kid` a wallet has to look up in `metadata.openid_credential_verifier.jwks`. */
  signingKeyId: string | null;
}

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
 * but no key a wallet can resolve verifies it. `federation-key` is the one
 * mutation that rewrites the header rather than a claim, dropping the key
 * material a wallet could otherwise verify with without consulting the
 * federation.
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

  if (options.mutation?.type === 'federation-key') {
    // Both key sources a wallet could use instead of the federation metadata:
    // the leaf certificate chain, and an inlined Trust Chain that would already
    // carry the Entity Configuration. `kid` is deliberately kept — it is the
    // lookup key into `metadata.openid_credential_verifier.jwks`.
    delete header.x5c;
    delete header.trust_chain;
    payload.client_id = toFederationClientId(payload.client_id);
  }

  const alg = header.alg ?? REQUEST_OBJECT_SIGNING_ALG;
  const signingKey =
    options.mutation?.type === 'invalid-signature'
      ? (await generateKeyPair(alg)).privateKey
      : await importJWK(options.signingPrivateJwk as JWK, alg);

  return new SignJWT(payload).setProtectedHeader({ ...header, alg }).sign(signingKey);
}

/**
 * Re-prefixes a `client_id` with `openid_federation`, replacing whichever Client
 * Identifier Prefix it carried. The identifier itself is left untouched, so it
 * keeps matching the engagement `client_id`, the Request Object `iss` and the
 * Entity Configuration `sub` once a wallet strips the prefix.
 */
function toFederationClientId(clientId: unknown): string {
  if (typeof clientId !== 'string' || clientId.length === 0) {
    throw new Error('Request Object is missing a client_id to switch to the openid_federation prefix');
  }

  const { clientId: unprefixed } = extractClientIdPrefix(clientId);
  return `${OPENID_FEDERATION_CLIENT_ID_PREFIX}:${unprefixed}`;
}

/**
 * Describes the federation-signed Request Object that was actually served, for
 * the `federation-key` fault evidence. Read back from the serialized artifact
 * rather than from the intended mutation, so the evidence can never claim a
 * header shape the wallet did not receive.
 */
export function describeFederationKeyRequestObject(jwt: string): FederationKeyMutationResult & { hasX5c: boolean } {
  const header = decodeProtectedHeader(jwt);
  const clientId = decodeJwt(jwt).client_id;

  return {
    clientId: typeof clientId === 'string' ? clientId : '',
    hasX5c: header.x5c !== undefined,
    signingKeyId: header.kid ?? null
  };
}
