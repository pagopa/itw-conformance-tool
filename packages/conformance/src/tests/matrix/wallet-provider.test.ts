import { loadConfig } from '@itw-conformance-tool/config';
import {
  itWalletMetadataV1_3,
  type ItWalletEntityConfigurationClaims,
  type ItWalletMetadataV1_3
} from '@pagopa/io-wallet-oid-federation';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify
} from 'jose';
import { beforeAll, describe, expect, test } from 'vitest';

import { isHttpsUrl, isObject } from '../../helpers/general.js';

const permittedEntityConfigurationSignatureAlgorithms = ['ES256', 'ES384', 'ES512'];

describe('Test Cases for Wallet Provider Backend', () => {
  const config = loadConfig();
  const walletProviderUrl = config['wallet-provider'].url;

  let entityConfiguration: string;
  let entityConfigurationResponse: Response;

  beforeAll(async () => {
    entityConfigurationResponse = await fetch(new URL('/.well-known/openid-federation', walletProviderUrl), {
      signal: AbortSignal.timeout(10_000)
    });

    entityConfiguration = await entityConfigurationResponse.text();
  });

  const decodeEntityConfiguration = (entityConfiguration: string): ItWalletEntityConfigurationClaims => {
    return decodeJwt<ItWalletEntityConfigurationClaims>(entityConfiguration);
  };

  const expectWalletMetadata = (metadata: ItWalletEntityConfigurationClaims['metadata']): ItWalletMetadataV1_3 => {
    const metadataResult = itWalletMetadataV1_3.safeParse(metadata);

    if (!metadataResult.success) {
      const validationErrors = metadataResult.error.issues.map(
        ({ message, path }) => `- ${path.length === 0 ? 'metadata' : `metadata.${path.join('.')}`}: ${message}`
      );

      expect.fail(
        ['Entity Configuration metadata must conform to the IT Wallet Metadata schema:', ...validationErrors].join('\n')
      );
    }

    return metadataResult.data;
  };

  test('WP_001: Entity Configuration publication', () => {
    expect(entityConfigurationResponse.status, 'Entity Configuration endpoint must return HTTP 200').toBe(200);
    expect(
      entityConfigurationResponse.headers.get('content-type'),
      'Entity Configuration response must use the application/entity-statement+jwt media type'
    ).toMatch(/^application\/entity-statement\+jwt(?:;|$)/i);
    expect(entityConfiguration, 'Entity Configuration response must be a compact JWT').toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
  });

  test('WP_002: Entity Configuration cryptography', async () => {
    const claims = decodeEntityConfiguration(entityConfiguration);
    const protectedHeader = decodeProtectedHeader(entityConfiguration);

    expect(claims.iss, 'Entity Configuration must contain a string issuer claim').toEqual(expect.any(String));
    expect(claims.sub, 'Entity Configuration subject must equal its issuer').toBe(claims.iss);
    expect(claims.jwks, 'Entity Configuration must contain a JWKS with a keys array').toEqual(
      expect.objectContaining({ keys: expect.any(Array) })
    );

    expect(protectedHeader.typ, 'Entity Configuration JWT type must be entity-statement+jwt').toBe(
      'entity-statement+jwt'
    );

    await jwtVerify(entityConfiguration, createLocalJWKSet(claims.jwks), {
      issuer: claims.iss,
      requiredClaims: ['exp', 'iat'],
      subject: claims.iss
    });
  });

  test('WP_002a: Entity Configuration JWT alg header parameter', () => {
    const { alg } = decodeProtectedHeader(entityConfiguration);

    expect(alg, 'Entity Configuration JWT signing algorithm must be ES256, ES384, or ES512').toBeOneOf(
      permittedEntityConfigurationSignatureAlgorithms
    );
    expect(alg, 'Entity Configuration JWT must not use the unsecured none algorithm').not.toBe('none');
  });

  test('WP_002b: Entity Configuration JWT kid header parameter', async () => {
    const claims = decodeEntityConfiguration(entityConfiguration);
    const { kid } = decodeProtectedHeader(entityConfiguration);

    expect(kid, 'Entity Configuration JWT header must contain a string kid').toEqual(expect.any(String));

    const signingKey = claims.jwks.keys.find((key) => key.kid === kid);

    expect(signingKey, 'Entity Configuration JWT kid must identify a public key in the JWKS').toBeDefined();
    if (!signingKey) {
      throw new Error('Entity Configuration signing key is missing from the JWKS');
    }

    await expect(
      calculateJwkThumbprint(signingKey),
      'Entity Configuration JWT kid must equal the signing public key thumbprint'
    ).resolves.toBe(kid);
  });

  test('WP_002c: Entity Configuration JWT typ header parameter', () => {
    const { typ } = decodeProtectedHeader(entityConfiguration);

    expect(typ, 'Entity Configuration JWT type must be entity-statement+jwt').toBe('entity-statement+jwt');
  });

  test('WP_002d: Entity Configuration issuer and subject payload claims', () => {
    const { iss, sub } = decodeEntityConfiguration(entityConfiguration);

    expect(iss, 'Entity Configuration issuer must equal the Wallet Provider public URL').toBe(walletProviderUrl);
    expect(sub, 'Entity Configuration subject must equal the Wallet Provider public URL').toBe(walletProviderUrl);
  });

  test('WP_002e: Entity Configuration validity', () => {
    const { exp, iat } = decodeEntityConfiguration(entityConfiguration);
    const now = Math.floor(Date.now() / 1_000);

    expect(iat, 'Entity Configuration issued-at claim must be a Unix timestamp').toSatisfy(Number.isSafeInteger);
    expect(exp, 'Entity Configuration expiration claim must be a Unix timestamp').toSatisfy(Number.isSafeInteger);
    expect(iat, 'Entity Configuration issued-at claim must not be in the future').toBeLessThanOrEqual(now);
    expect(exp, 'Entity Configuration expiration claim must be in the future').toBeGreaterThan(now);
    expect(exp, 'Entity Configuration expiration claim must follow its issued-at claim').toBeGreaterThan(iat);
  });

  test('WP_002f: Entity Configuration authority hints', () => {
    const { authority_hints: authorityHints } = decodeEntityConfiguration(entityConfiguration);

    expect(authorityHints, 'Entity Configuration authority hints must be an array').toEqual(expect.any(Array));
    expect(
      authorityHints,
      'Entity Configuration must identify at least one immediate superior entity'
    ).not.toHaveLength(0);

    for (const authorityHint of authorityHints as string[]) {
      expect(authorityHint, 'Each authority hint must be an HTTPS Entity Identifier URL').toSatisfy((value) =>
        isHttpsUrl(value, false)
      );
    }
  });

  test('WP_002g: Entity Configuration public keys', async () => {
    const { jwks } = decodeEntityConfiguration(entityConfiguration);
    const { alg } = decodeProtectedHeader(entityConfiguration);

    expect(jwks, 'Entity Configuration must contain a JWKS object').toSatisfy(isObject);
    expect(jwks, 'Entity Configuration JWKS must contain a keys array').toEqual(
      expect.objectContaining({ keys: expect.any(Array) })
    );

    const publicKeys = jwks.keys;
    expect(publicKeys, 'Entity Configuration JWKS must contain at least one public key').not.toHaveLength(0);

    for (const key of publicKeys) {
      expect(key.d, 'Entity Configuration JWKS must not contain private key material').toBeUndefined();
      expect(key.k, 'Entity Configuration JWKS must not contain symmetric keys').toBeUndefined();
      await expect(
        importJWK(key, key.alg ?? alg),
        'Each Entity Configuration key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_002h: Entity Configuration metadata', () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);

    expect(
      metadata.wallet_solution,
      'Entity Configuration metadata must contain wallet_solution metadata'
    ).toBeDefined();

    const federationEntity = metadata.federation_entity;
    if (federationEntity === undefined) {
      return;
    }

    expect(federationEntity, 'federation_entity metadata must be an object when present').toSatisfy(isObject);

    expect(
      Object.values(federationEntity),
      'federation_entity metadata must not contain null-valued parameters'
    ).not.toContain(null);

    const federationEndpoints = [
      'federation_fetch_endpoint',
      'federation_list_endpoint',
      'federation_resolve_endpoint',
      'federation_trust_mark_status_endpoint',
      'federation_trust_mark_list_endpoint',
      'federation_trust_mark_endpoint',
      'federation_historical_keys_endpoint'
    ];

    for (const endpointName of federationEndpoints) {
      const endpoint = federationEntity[endpointName];
      if (endpoint !== undefined) {
        expect(endpoint, `${endpointName} must be an HTTPS URL without a fragment`).toSatisfy(isHttpsUrl);
      }
    }
  });

  test('WP_003: Metadata key usage', () => {
    const { jwks } = decodeJwt<ItWalletEntityConfigurationClaims>(entityConfiguration);

    for (const key of jwks.keys) {
      expect(key.use, 'Entity Configuration public keys must be designated for signing or encryption').toBeOneOf([
        'sig',
        'enc'
      ]);
    }
  });

  test('WP_004: Metadata key reference', () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const keyReferences = ['jwks', 'jwks_uri', 'signed_jwks_uri'];
    const presentKeyReferences = keyReferences.filter((claim) => metadata.wallet_solution?.[claim] !== undefined);

    expect(
      presentKeyReferences,
      'wallet_solution metadata must contain exactly one public key reference: jwks, jwks_uri, or signed_jwks_uri'
    ).toHaveLength(1);
  });

  test('WP_004a: JWKS by value', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);

    expect(
      metadata.wallet_solution,
      'Entity Configuration metadata must contain wallet_solution metadata'
    ).toBeDefined();

    const jwks = metadata.wallet_solution?.jwks;
    if (jwks === undefined) {
      return;
    }

    expect(jwks, 'wallet_solution jwks claim must contain a JWKS object').toSatisfy(isObject);
    const keys = jwks.keys;
    expect(keys, 'wallet_solution jwks claim must contain a keys array').toEqual(expect.any(Array));
    if (!Array.isArray(keys)) {
      throw new Error('wallet_solution jwks claim does not contain a keys array');
    }

    expect(keys, 'wallet_solution jwks claim must contain at least one public key').not.toHaveLength(0);
    for (const key of keys) {
      await expect(
        importJWK(key),
        'Each wallet_solution jwks claim key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_004b: JWKS by reference', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);

    expect(
      metadata.wallet_solution,
      'Entity Configuration metadata must contain wallet_solution metadata'
    ).toBeDefined();

    const jwksUri = metadata.wallet_solution?.jwks_uri;
    if (jwksUri === undefined) {
      return;
    }

    expect(jwksUri, 'wallet_solution jwks_uri claim must be an HTTPS URL').toSatisfy(isHttpsUrl);
    if (typeof jwksUri !== 'string') {
      throw new Error('wallet_solution jwks_uri claim is not a string');
    }

    const response = await fetch(jwksUri, { signal: AbortSignal.timeout(10_000) });
    expect(response.ok, 'wallet_solution jwks_uri must resolve successfully').toBe(true);

    const jwksDocument = (await response.json()) as Record<string, unknown>;
    expect(jwksDocument, 'wallet_solution jwks_uri must resolve to a JWKS object').toSatisfy(isObject);

    const keys = jwksDocument.keys;
    expect(keys, 'wallet_solution jwks_uri JWKS must contain a keys array').toEqual(expect.any(Array));
    if (!Array.isArray(keys)) {
      throw new Error('wallet_solution jwks_uri JWKS does not contain a keys array');
    }

    expect(keys, 'wallet_solution jwks_uri JWKS must contain at least one public key').not.toHaveLength(0);
    for (const key of keys) {
      await expect(
        importJWK(key),
        'Each wallet_solution jwks_uri JWKS key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_004c: Signed JWKS URI', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);

    const signedJwksUri = metadata.wallet_solution?.signed_jwks_uri;
    if (signedJwksUri === undefined) {
      return;
    }

    expect(signedJwksUri, 'wallet_solution signed_jwks_uri claim must be an HTTPS URL').toSatisfy(isHttpsUrl);
    if (typeof signedJwksUri !== 'string') {
      throw new Error('wallet_solution signed_jwks_uri claim is not a string');
    }

    const response = await fetch(signedJwksUri, { signal: AbortSignal.timeout(10_000) });
    expect(response.status, 'wallet_solution signed_jwks_uri must return HTTP 200').toBe(200);
    expect(
      response.headers.get('content-type'),
      'wallet_solution signed_jwks_uri response must use the application/jwk-set+jwt media type'
    ).toMatch(/^application\/jwk-set\+jwt(?:;|$)/i);

    const signedJwks = await response.text();
    expect(signedJwks, 'wallet_solution signed_jwks_uri response must be a compact JWT').toMatch(
      /^[^.]+\.[^.]+\.[^.]+$/
    );
    await jwtVerify(signedJwks, createLocalJWKSet(ec.jwks));

    const jwksDocument = decodeJwt(signedJwks);
    expect(jwksDocument, 'wallet_solution signed_jwks_uri JWT payload must be a JWKS object').toSatisfy(isObject);

    const keys = jwksDocument.keys;
    expect(keys, 'wallet_solution signed_jwks_uri JWT payload must contain a keys array').toEqual(expect.any(Array));
    if (!Array.isArray(keys)) {
      throw new Error('wallet_solution signed_jwks_uri JWT payload does not contain a keys array');
    }

    expect(keys, 'wallet_solution signed_jwks_uri JWT payload must contain at least one public key').not.toHaveLength(
      0
    );

    for (const key of keys) {
      await expect(importJWK(key), 'Each signed_jwks_uri JWKS key must be a valid public JWK').resolves.toBeDefined();
    }
  });
});
