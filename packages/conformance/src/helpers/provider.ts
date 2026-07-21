import {
  itWalletMetadataV1_3,
  type ItWalletEntityConfigurationClaims,
  type ItWalletMetadataV1_3
} from '@pagopa/io-wallet-oid-federation';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify, type JWK } from 'jose';
import { expect } from 'vitest';

import { isHttpsUrl, isObject } from './general.js';

export function decodeEntityConfiguration(entityConfiguration: string): ItWalletEntityConfigurationClaims {
  return decodeJwt<ItWalletEntityConfigurationClaims>(entityConfiguration);
}

export function expectWalletMetadata(metadata: unknown): ItWalletMetadataV1_3 {
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
}

export function expectPublicJwk(key: JWK, location: string): void {
  expect(key.d, `${location} must not contain private key material`).toBeUndefined();
  expect(key.k, `${location} must not contain symmetric keys`).toBeUndefined();
}

export async function resolveWalletSolutionJwks(
  entityConfigurationClaims: ItWalletEntityConfigurationClaims,
  walletSolution: NonNullable<ItWalletMetadataV1_3['wallet_solution']>
): Promise<JWK[]> {
  const keyReferences = [walletSolution.jwks, walletSolution.jwks_uri, walletSolution.signed_jwks_uri].filter(
    (reference) => reference !== undefined
  );
  expect(
    keyReferences,
    'wallet_solution metadata must contain exactly one public key reference: jwks, jwks_uri, or signed_jwks_uri'
  ).toHaveLength(1);

  if (walletSolution.jwks !== undefined) {
    expect(walletSolution.jwks, 'wallet_solution jwks claim must contain a JWKS object').toSatisfy(isObject);
    const keys = walletSolution.jwks.keys;
    expect(keys, 'wallet_solution jwks claim must contain a keys array').toEqual(expect.any(Array));
    if (!Array.isArray(keys)) {
      throw new Error('wallet_solution jwks claim does not contain a keys array');
    }

    return keys;
  }

  if (walletSolution.jwks_uri !== undefined) {
    expect(walletSolution.jwks_uri, 'wallet_solution jwks_uri claim must be an HTTPS URL').toSatisfy(isHttpsUrl);

    const response = await fetch(walletSolution.jwks_uri, { signal: AbortSignal.timeout(10_000) });
    expect(response.ok, 'wallet_solution jwks_uri must resolve successfully').toBe(true);

    const jwksDocument = (await response.json()) as { keys?: JWK[] };
    expect(jwksDocument, 'wallet_solution jwks_uri must resolve to a JWKS object').toSatisfy(isObject);
    expect(jwksDocument.keys, 'wallet_solution jwks_uri JWKS must contain a keys array').toEqual(expect.any(Array));
    if (!Array.isArray(jwksDocument.keys)) {
      throw new Error('wallet_solution jwks_uri JWKS does not contain a keys array');
    }

    return jwksDocument.keys;
  }

  if (walletSolution.signed_jwks_uri !== undefined) {
    expect(walletSolution.signed_jwks_uri, 'wallet_solution signed_jwks_uri claim must be an HTTPS URL').toSatisfy(
      isHttpsUrl
    );

    const response = await fetch(walletSolution.signed_jwks_uri, { signal: AbortSignal.timeout(10_000) });
    expect(response.status, 'wallet_solution signed_jwks_uri must return HTTP 200').toBe(200);
    expect(
      response.headers.get('content-type'),
      'wallet_solution signed_jwks_uri response must use the application/jwk-set+jwt media type'
    ).toMatch(/^application\/jwk-set\+jwt(?:;|$)/i);

    const signedJwks = await response.text();
    expect(signedJwks, 'wallet_solution signed_jwks_uri response must be a compact JWT').toMatch(
      /^[^.]+\.[^.]+\.[^.]+$/
    );

    const { kid, typ } = decodeProtectedHeader(signedJwks);
    expect(typ, 'wallet_solution signed_jwks_uri JWT type must be jwk-set+jwt').toBe('jwk-set+jwt');
    expect(kid, 'wallet_solution signed_jwks_uri JWT header must contain a string kid').toEqual(expect.any(String));

    const entityIdentifier = entityConfigurationClaims.sub;
    expect(
      entityIdentifier,
      'Entity Configuration subject must identify the entity that publishes the signed JWKS'
    ).toEqual(expect.any(String));

    await jwtVerify(signedJwks, createLocalJWKSet(entityConfigurationClaims.jwks), {
      issuer: entityIdentifier,
      requiredClaims: ['iss', 'sub'],
      subject: entityIdentifier
    });

    const jwksDocument = decodeJwt<{ keys?: JWK[] }>(signedJwks);
    expect(jwksDocument, 'wallet_solution signed_jwks_uri JWT payload must be a JWKS object').toSatisfy(isObject);
    expect(jwksDocument.keys, 'wallet_solution signed_jwks_uri JWT payload must contain a keys array').toEqual(
      expect.any(Array)
    );
    if (!Array.isArray(jwksDocument.keys)) {
      throw new Error('wallet_solution signed_jwks_uri JWT payload does not contain a keys array');
    }

    return jwksDocument.keys;
  }

  throw new Error('wallet_solution metadata does not contain a public key reference');
}
