import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { ItWalletMetadataV1_4 } from '@pagopa/io-wallet-oid-federation';
import type { Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';

/**
 * Single source of truth for everything this Relying Party advertises about
 * itself.
 *
 * The same capabilities are published twice — in the federation Entity
 * Configuration (`metadata.openid_credential_verifier`) and inline in every
 * Request Object (`client_metadata`) — and a wallet is entitled to compare
 * them. Building both from this module is what keeps them from drifting apart,
 * and what keeps them honest about what the Verifier can actually process:
 * `utils/vp-token.ts` implements `dc+sd-jwt` over ES256 and nothing else, so
 * that is precisely what is offered.
 */

/**
 * A published JWK. `kid` is mandatory: a wallet selecting the encryption key
 * out of `jwks` identifies it by `kid`, and echoes that value in the JWE
 * header.
 */
export type PublishedJwk = Jwk & { kid: string };

/** Endpoint paths, attested in the Entity Configuration and served by `routes/`. */
export const REQUEST_URI_PATH = '/auth/request';
export const RESPONSE_URI_PATH = '/auth/response';
export const REDIRECT_URI_PATH = '/callback';

export const CLIENT_NAME = 'PagoPa S.p.A.';
export const LOGO_URI = 'https://io.italia.it/assets/img/io-it-logo-blue.svg';

/**
 * JWE `enc` algorithms accepted for the encrypted Authorization Response.
 *
 * IT Wallet requires the `direct_post.jwt` response to be encrypted with
 * ECDH-ES key agreement on P-256 and AES-GCM content encryption, preferring
 * `A256GCM` — so `A256GCM` leads and no CBC-HMAC variant is offered.
 */
export const RESPONSE_ENCRYPTION_ENC_VALUES_SUPPORTED: readonly string[] = ['A256GCM', 'A128GCM'];

/**
 * JWE key-agreement `alg` values accepted for the encrypted Authorization
 * Response.
 *
 * Advertised explicitly since IT Wallet 1.4, which names
 * `encrypted_response_alg_values_supported` in the normative `client_metadata`
 * example and mandates ECDH-ES on P-256. It could in principle be derived from
 * the `alg` member of the encryption JWK the wallet selects out of `jwks`, but
 * a wallet is entitled to read the capability off the metadata without first
 * parsing a key.
 */
export const RESPONSE_ENCRYPTION_ALG_VALUES_SUPPORTED: readonly string[] = ['ECDH-ES'];

/**
 * Credential formats and signing algorithms this Verifier can actually verify.
 * Kept deliberately narrow: `VpTokenVerifier` rejects every format other than
 * `dc+sd-jwt` and builds ES256 verifiers only, so advertising anything else
 * would invite a presentation the Relying Party then answers with a 403.
 */
export function buildVpFormatsSupported(): Record<string, Record<string, string[]>> {
  return {
    'dc+sd-jwt': {
      'kb-jwt_alg_values': ['ES256'],
      'sd-jwt_alg_values': ['ES256']
    }
  };
}

export interface BuildVerifierEntityConfigurationMetadataOptions {
  /** Relying Party entity identifier, which is also the Entity Configuration `sub`. */
  baseUrl: string;
  encryptionJwk: PublishedJwk;
  erasure_endpoint: string | undefined;
  /** Attested `redirect_uris`; overridden by the `unattested-redirect-uri` fault. */
  redirectUris: string[];
  /** Attested `request_uris`; overridden by the `unattested-request-uri` fault. */
  requestUris: string[];
  /** Attested `response_uris`; overridden by the `unattested-response-uri` fault. */
  responseUris: string[];
  signingJwk: PublishedJwk;
}

/**
 * Builds `metadata` for the federation Entity Configuration.
 *
 * `jwks` publishes both the signing and the encryption key: a wallet resolving
 * this Relying Party through the Trust Chain needs the signing key to verify a
 * Request Object that carries no `x5c` (WP_084), and the encryption key to
 * encrypt the Authorization Response.
 */
export function buildVerifierEntityConfigurationMetadata(
  options: BuildVerifierEntityConfigurationMetadataOptions
): ItWalletMetadataV1_4 {
  const { baseUrl, encryptionJwk, erasure_endpoint, redirectUris, requestUris, responseUris, signingJwk } = options;

  return {
    federation_entity: {
      contacts: ['info@pagopa.it'],
      homepage_uri: 'https://io.italia.it',
      logo_uri: LOGO_URI,
      organization_name: CLIENT_NAME,
      policy_uri: 'https://io.italia.it/privacy-policy'
    },
    openid_credential_verifier: {
      application_type: 'web',
      client_id: baseUrl,
      client_name: CLIENT_NAME,
      encrypted_response_alg_values_supported: [...RESPONSE_ENCRYPTION_ALG_VALUES_SUPPORTED],
      encrypted_response_enc_values_supported: [...RESPONSE_ENCRYPTION_ENC_VALUES_SUPPORTED],
      jwks: {
        keys: [signingJwk, encryptionJwk]
      },
      logo_uri: LOGO_URI,
      erasure_endpoint,
      redirect_uris: redirectUris,
      request_uris: requestUris,
      response_uris: responseUris,
      vp_formats_supported: buildVpFormatsSupported()
    }
  } satisfies ItWalletMetadataV1_4;
}

/**
 * Builds the `client_metadata` inlined in the Request Object.
 *
 * `jwks` carries the encryption key alone. OpenID4VP forbids using keys from
 * `client_metadata.jwks` to verify the Authorization Request signature, so
 * publishing the signing key here would be meaningless at best.
 *
 * Deliberately absent: `request_uris` and `response_uris`. Those are attested
 * endpoint lists, and a copy the Relying Party signs into its own Request
 * Object attests nothing — a wallet that trusted it instead of the Entity
 * Configuration would silently pass WP_081 and WP_091a, whose faults rewrite
 * only the Entity Configuration.
 */
export function buildRequestObjectClientMetadata(options: {
  baseUrl: string;
  encryptionJwk: PublishedJwk;
}): NonNullable<Openid4vpAuthorizationRequestPayload['client_metadata']> {
  return {
    application_type: 'web',
    client_id: options.baseUrl,
    client_name: CLIENT_NAME,
    encrypted_response_alg_values_supported: [...RESPONSE_ENCRYPTION_ALG_VALUES_SUPPORTED],
    encrypted_response_enc_values_supported: [...RESPONSE_ENCRYPTION_ENC_VALUES_SUPPORTED],
    jwks: {
      keys: [options.encryptionJwk]
    },
    logo_uri: LOGO_URI,
    vp_formats_supported: buildVpFormatsSupported()
  };
}
