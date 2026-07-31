import { sha256 } from '@itw-conformance-tool/crypto';
import { decodeJwt, decodeProtectedHeader, generateKeyPair, importJWK, SignJWT } from 'jose';

import type { ActiveRpFault } from '../faults/rp-fault-store.js';
import type { RequestObjectOmittedParameter } from '@itw-conformance-tool/faults';
import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { JWK } from 'jose';

const REQUEST_OBJECT_SIGNING_ALG = 'ES256';

/**
 * The OpenID Federation Client Identifier Prefix. A `client_id` carrying it tells
 * the wallet to resolve the Relying Party — and its signing key — through the
 * federation Trust Chain, rather than from the `x5c` certificate chain the
 * `x509_hash` prefix points at.
 */
const OPENID_FEDERATION_CLIENT_ID_PREFIX = 'openid_federation';

/**
 * The Client Identifier Prefix IT Wallet uses by default. It tells the wallet
 * to take the verification key from the `x5c` certificate chain in the Request
 * Object header, which IT Wallet 1.4 requires precisely for this prefix.
 */
const X509_HASH_CLIENT_ID_PREFIX = 'x509_hash';

/**
 * Trust mechanism the engagement announces, and therefore the one the wallet is
 * expected to use.
 *
 * The two are alternatives, not layers: `x509_hash` establishes trust through
 * the certificate chain and carries the Verifier metadata by value in the
 * Request Object, while `openid_federation` establishes it through the
 * federation Trust Chain and puts the metadata in the Entity Configuration. A
 * scenario picks the one it means to exercise; nothing else in the flow changes.
 */
export type ClientIdPrefix = 'openid_federation' | 'x509_hash';

/** The prefix used when a scenario does not ask for one — the IT Wallet nominal path. */
export const DEFAULT_CLIENT_ID_PREFIX: ClientIdPrefix = 'x509_hash';

/**
 * Builds the `x509_hash` `client_id`: the base64url-encoded SHA-256 hash of the
 * Relying Party's DER-encoded leaf certificate.
 *
 * The identifier is a *hash*, not a URL. A wallet that resolves this prefix
 * hashes the leaf certificate it was handed in the Request Object header `x5c`
 * and requires the result to equal this value, so it is derived from the very
 * certificate that goes into `x5c` and matches it by construction.
 *
 * Nothing about the Relying Party's identity can be read out of it: the entity
 * identifier lives in `iss`, in the Entity Configuration `sub` and in
 * `client_metadata.client_id`, never behind this prefix.
 *
 * @param certificateBase64Der - The leaf certificate as base64-encoded DER, exactly as published in the Request Object header `x5c`.
 * @returns The prefixed client identifier.
 */
export function toX509HashClientId(certificateBase64Der: string): string {
  const thumbprint = Buffer.from(sha256(Buffer.from(certificateBase64Der, 'base64'))).toString('base64url');

  return `${X509_HASH_CLIENT_ID_PREFIX}:${thumbprint}`;
}

/**
 * Builds a `client_id` behind the `openid_federation` prefix.
 *
 * Unlike `x509_hash`, this prefix carries the Relying Party entity identifier
 * itself — that is the whole point: it tells the wallet to resolve the Relying
 * Party, and its signing key, through the federation Trust Chain. So the entity
 * identifier has to be supplied rather than recovered from the `x509_hash`
 * `client_id`, which is a certificate hash and carries no identifier at all.
 *
 * @param entityId - The Relying Party base URL, which is also its Entity Configuration `sub`.
 */
export function toFederationClientId(entityId: string): string {
  if (entityId.length === 0) {
    throw new Error('An entity identifier is required to build an openid_federation client_id');
  }

  return `${OPENID_FEDERATION_CLIENT_ID_PREFIX}:${entityId}`;
}

/**
 * A syntactically valid entity identifier that is not the `sub` of the Relying
 * Party Entity Configuration: `.invalid` is reserved by RFC 2606, so it can
 * never resolve to a real federation participant. Used only by the
 * `request-object-invalid-client-id` fault (WP_086), which rewrites the Request
 * Object `iss`.
 *
 * Under the `x509_hash` prefix the `client_id` is a certificate hash and carries
 * no identifier, so `iss` is checked against the Entity Configuration `sub`
 * alone; under `openid_federation` it is checked against both.
 */
export const MISMATCHED_REQUEST_OBJECT_ISSUER = 'https://wp-086-client-id-mismatch.itw-conformance-tool.invalid';

/** Request Object mutation requested by an active Relying Party fault profile. */
export type RequestObjectMutation =
  | { type: 'invalid-signature' }
  | { type: 'mismatched-issuer' }
  | { type: 'omit-parameter'; parameter: RequestObjectOmittedParameter };

/** How a wallet can resolve the key that signed the served Request Object. */
export interface RequestObjectKeyResolution {
  /** The prefix the `client_id` claim carries, or `null` when it carries none. */
  clientIdPrefix: ClientIdPrefix | null;
  /** Whether the header offers a certificate chain to verify with. */
  hasX5c: boolean;
  /** `kid` a wallet has to look up in `metadata.openid_credential_verifier.jwks` when there is no `x5c`. */
  signingKeyId: string | null;
}

interface SignRequestObjectOptions {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Signs with a throwaway key instead, so no key a wallet can resolve verifies the result. */
  signWithEphemeralKey?: boolean;
  signingPrivateJwk: Jwk;
}

/**
 * Re-signs a Request Object with the header it was handed.
 *
 * The header is reused verbatim — including `kid`, `x5c` or their absence — so
 * a wallet resolves the verification key exactly as the caller intended.
 */
async function signRequestObject(options: SignRequestObjectOptions): Promise<string> {
  const alg = (options.header.alg as string | undefined) ?? REQUEST_OBJECT_SIGNING_ALG;
  const signingKey = options.signWithEphemeralKey
    ? (await generateKeyPair(alg)).privateKey
    : await importJWK(options.signingPrivateJwk as JWK, alg);

  return new SignJWT(options.payload).setProtectedHeader({ ...options.header, alg }).sign(signingKey);
}

/**
 * Splits a Request Object JWT into the parts the rewrites below work on.
 *
 * `b64` (RFC 7797 unencoded payload) never appears in a JAR and is typed more
 * narrowly on the signing side than on the decoding side, so it is dropped
 * rather than carried over.
 */
function decomposeRequestObject(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const { b64, ...header } = decodeProtectedHeader(jwt);
  void b64;

  return { header: header as Record<string, unknown>, payload: { ...decodeJwt(jwt) } };
}

export interface ReissueRequestObjectOptions {
  /** The stored Request Object JWT whose header and claims are reused. */
  jwt: string;
  mutation?: RequestObjectMutation;
  /** The Relying Party signing key the stored Request Object was signed with. */
  signingPrivateJwk: Jwk;
  /** `wallet_nonce` to echo back, as sent by the wallet on a `request_uri_method=post` retrieval. */
  walletNonce?: string;
}

/**
 * Rebuilds the stored Request Object so it can carry retrieval-time data (the
 * wallet's `wallet_nonce`) and/or an active fault mutation, then re-signs it
 * with the same protected header the stored Request Object used.
 *
 * The header is reused verbatim, so the key resolution path the engagement
 * announced — certificate chain or federation `kid` — survives the rewrite.
 * Only `invalid-signature` changes the signing key, and it changes nothing
 * else: the resulting JWT is well formed and its claims are nominal, but no key
 * a wallet can resolve verifies it.
 */
export async function reissueRequestObjectJwt(options: ReissueRequestObjectOptions): Promise<string> {
  const { header, payload } = decomposeRequestObject(options.jwt);

  if (options.walletNonce !== undefined) {
    payload.wallet_nonce = options.walletNonce;
  }

  if (options.mutation?.type === 'mismatched-issuer') {
    payload.iss = MISMATCHED_REQUEST_OBJECT_ISSUER;
  }

  if (options.mutation?.type === 'omit-parameter') {
    delete payload[options.mutation.parameter];
  }

  return signRequestObject({
    header,
    payload,
    signWithEphemeralKey: options.mutation?.type === 'invalid-signature',
    signingPrivateJwk: options.signingPrivateJwk
  });
}

/**
 * Maps an active Relying Party fault profile onto the mutation the served
 * Request Object must carry. Profiles applied elsewhere in the flow (Entity
 * Configuration, Authorization Response) leave the Request Object nominal.
 *
 * @param fault - The currently active Relying Party fault, if any.
 * @returns The fault and the mutation it requires, or `undefined` when the Request Object stays nominal.
 */
export function resolveRequestObjectMutation(
  fault: ActiveRpFault | undefined
): { fault: ActiveRpFault; mutation: RequestObjectMutation } | undefined {
  if (!fault) return undefined;

  switch (fault.profile.type) {
    case 'request-object-invalid-signature':
      return { fault, mutation: { type: 'invalid-signature' } };
    case 'request-object-invalid-client-id':
      return { fault, mutation: { type: 'mismatched-issuer' } };
    case 'request-object-missing-parameter':
      return { fault, mutation: { type: 'omit-parameter', parameter: fault.profile.parameter } };
    default:
      return undefined;
  }
}

/**
 * Reads the Client Identifier Prefix out of a `client_id`.
 *
 * @param clientId - The `client_id` claim of a Request Object.
 * @returns The prefix, or `null` when the value carries none this Relying Party can produce.
 */
export function readClientIdPrefix(clientId: unknown): ClientIdPrefix | null {
  if (typeof clientId !== 'string') return null;
  if (clientId.startsWith(`${OPENID_FEDERATION_CLIENT_ID_PREFIX}:`)) return 'openid_federation';
  if (clientId.startsWith(`${X509_HASH_CLIENT_ID_PREFIX}:`)) return 'x509_hash';

  return null;
}

/**
 * Describes how a wallet can resolve the key that signed the Request Object it
 * was just served.
 *
 * Read back from the serialized artifact rather than from the requested prefix,
 * so the evidence can never claim a header shape the wallet did not receive.
 */
export function describeRequestObjectKeyResolution(jwt: string): RequestObjectKeyResolution {
  const header = decodeProtectedHeader(jwt);

  return {
    clientIdPrefix: readClientIdPrefix(decodeJwt(jwt).client_id),
    hasX5c: header.x5c !== undefined,
    signingKeyId: header.kid ?? null
  };
}
