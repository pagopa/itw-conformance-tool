import { createHash, generateKeyPairSync } from 'node:crypto';

import { convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '@itw-conformance-tool/crypto';
import { describe, expect, it } from 'vitest';

import { toFederationClientId, toX509HashClientId } from '../request-object.js';

import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';

async function createCertificateBase64Der(): Promise<string> {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...(privateKey.export({ format: 'jwk' }) as JWK), alg: 'ES256', kid: 'rp-signing-key', use: 'sig' };

  return convertPemToBase64Der(await createSelfSignedCertificateFromJwk(jwk));
}

describe('toX509HashClientId', () => {
  it('is the base64url SHA-256 of the DER certificate, which is the check a wallet performs', async () => {
    const certificate = await createCertificateBase64Der();

    // Recomputed independently of the implementation: this is exactly what a
    // wallet resolving the x509_hash prefix does with the `x5c` entry it was
    // handed, and the value it requires `client_id` to equal.
    const expected = createHash('sha256').update(Buffer.from(certificate, 'base64')).digest('base64url');

    expect(toX509HashClientId(certificate)).toBe(`x509_hash:${expected}`);
  });

  it('carries no entity identifier', async () => {
    const clientId = toX509HashClientId(await createCertificateBase64Der());

    expect(clientId).not.toContain(RP_BASE_URL);
    expect(clientId).not.toContain('https://');
  });

  it('produces a base64url identifier of SHA-256 length', async () => {
    const clientId = toX509HashClientId(await createCertificateBase64Der());
    const identifier = clientId.slice('x509_hash:'.length);

    expect(identifier).toMatch(/^[A-Za-z0-9_-]+$/);
    // 32 bytes base64url-encoded, unpadded.
    expect(identifier).toHaveLength(43);
  });

  it('binds to the certificate, so a different certificate yields a different identifier', async () => {
    const [first, second] = await Promise.all([createCertificateBase64Der(), createCertificateBase64Der()]);

    expect(toX509HashClientId(first)).not.toBe(toX509HashClientId(second));
  });
});

describe('toFederationClientId', () => {
  it('carries the entity identifier, which is what points the wallet at the Trust Chain', () => {
    expect(toFederationClientId(RP_BASE_URL)).toBe(`openid_federation:${RP_BASE_URL}`);
  });

  it('rejects an empty entity identifier rather than emitting a bare prefix', () => {
    expect(() => toFederationClientId('')).toThrow(/entity identifier is required/);
  });
});
