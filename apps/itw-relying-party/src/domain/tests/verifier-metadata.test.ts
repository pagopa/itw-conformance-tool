import { itWalletMetadataV1_4 } from '@pagopa/io-wallet-oid-federation';
import { describe, expect, it } from 'vitest';

import {
  buildRequestObjectClientMetadata,
  buildVerifierEntityConfigurationMetadata,
  REDIRECT_URI_PATH,
  REQUEST_URI_PATH,
  RESPONSE_URI_PATH,
  type PublishedJwk
} from '../verifier-metadata.js';

const RP_BASE_URL = 'https://rp.example.org';

const SIGNING_JWK = { alg: 'ES256', crv: 'P-256', kid: 'rp-signing-key', kty: 'EC', use: 'sig', x: 'x', y: 'y' };
const ENCRYPTION_JWK = { alg: 'ECDH-ES', crv: 'P-256', kid: 'rp-enc-key', kty: 'EC', use: 'enc', x: 'x', y: 'y' };

function buildEntityConfigurationMetadata() {
  return buildVerifierEntityConfigurationMetadata({
    baseUrl: RP_BASE_URL,
    encryptionJwk: ENCRYPTION_JWK as PublishedJwk,
    redirectUris: [`${RP_BASE_URL}${REDIRECT_URI_PATH}`],
    requestUris: [`${RP_BASE_URL}${REQUEST_URI_PATH}`],
    responseUris: [`${RP_BASE_URL}${RESPONSE_URI_PATH}`],
    signingJwk: SIGNING_JWK as PublishedJwk
  });
}

function buildClientMetadata() {
  return buildRequestObjectClientMetadata({
    baseUrl: RP_BASE_URL,
    encryptionJwk: ENCRYPTION_JWK as PublishedJwk
  });
}

describe('verifier metadata', () => {
  it('advertises the same capabilities in the Entity Configuration and the Request Object', () => {
    const verifier = buildEntityConfigurationMetadata().openid_credential_verifier;
    const clientMetadata = buildClientMetadata();

    // A wallet may read either artifact. Two disagreeing capability sets leave
    // it with no safe choice.
    expect(clientMetadata.encrypted_response_enc_values_supported).toEqual(
      verifier.encrypted_response_enc_values_supported
    );
    expect(clientMetadata.encrypted_response_alg_values_supported).toEqual(
      verifier.encrypted_response_alg_values_supported
    );
    expect(clientMetadata.vp_formats_supported).toEqual(verifier.vp_formats_supported);
    expect(clientMetadata.client_name).toBe(verifier.client_name);
    expect(clientMetadata.logo_uri).toBe(verifier.logo_uri);
  });

  it('offers AES-GCM response encryption only, preferring A256GCM', () => {
    // IT Wallet mandates ECDH-ES on P-256 with AES-GCM; CBC-HMAC is not permitted.
    expect(buildClientMetadata().encrypted_response_enc_values_supported).toEqual(['A256GCM', 'A128GCM']);
  });

  it('advertises ECDH-ES key agreement explicitly', () => {
    // IT Wallet 1.4 names `encrypted_response_alg_values_supported` in the
    // normative client_metadata example: a wallet is entitled to read the
    // capability off the metadata rather than infer it from the JWK's own `alg`.
    expect(buildClientMetadata().encrypted_response_alg_values_supported).toEqual(['ECDH-ES']);
    expect(
      buildEntityConfigurationMetadata().openid_credential_verifier.encrypted_response_alg_values_supported
    ).toEqual(['ECDH-ES']);
  });

  it('offers only the format and algorithm the VP token verifier implements', () => {
    // VpTokenVerifier throws on any format other than dc+sd-jwt and builds ES256
    // verifiers only, so anything wider would invite a presentation the Relying
    // Party then answers with a 403.
    expect(buildClientMetadata().vp_formats_supported).toEqual({
      'dc+sd-jwt': { 'kb-jwt_alg_values': ['ES256'], 'sd-jwt_alg_values': ['ES256'] }
    });
  });

  it('keeps the attested endpoint lists out of the Request Object', () => {
    const clientMetadata = buildClientMetadata() as Record<string, unknown>;

    // Self-attestation attests nothing. A wallet trusting these instead of the
    // Entity Configuration would silently pass WP_081 and WP_091a, whose faults
    // rewrite only the Entity Configuration.
    expect(clientMetadata.request_uris).toBeUndefined();
    expect(clientMetadata.response_uris).toBeUndefined();
    expect(clientMetadata.redirect_uris).toBeUndefined();
  });

  it('publishes the encryption key alone in the Request Object', () => {
    // OpenID4VP forbids verifying the request signature with a key from
    // client_metadata.jwks, so publishing the signing key here would mislead.
    expect(buildClientMetadata().jwks.keys).toEqual([ENCRYPTION_JWK]);
  });

  it('publishes both keys in the Entity Configuration', () => {
    // A wallet resolving through the Trust Chain needs the signing key to verify
    // a Request Object carrying no x5c (WP_084), and the encryption key for the
    // Authorization Response.
    expect(buildEntityConfigurationMetadata().openid_credential_verifier.jwks.keys).toEqual([
      SIGNING_JWK,
      ENCRYPTION_JWK
    ]);
  });

  it('produces Entity Configuration metadata the IT Wallet 1.4 schema accepts', () => {
    expect(itWalletMetadataV1_4.safeParse(buildEntityConfigurationMetadata()).success).toBe(true);
  });

  it('identifies the Relying Party by entity identifier in both artifacts', () => {
    // The prefixed `client_id` is a certificate hash; this is where the entity
    // identifier is actually stated.
    expect(buildEntityConfigurationMetadata().openid_credential_verifier.client_id).toBe(RP_BASE_URL);
    expect(buildClientMetadata().client_id).toBe(RP_BASE_URL);
  });
});
