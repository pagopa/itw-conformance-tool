import { exportJWK, generateKeyPair, importX509, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { convertBase64DerToPem, convertPemToBase64Der, createSelfSignedCertificateFromJwk } from '../../utils/x509.js';

describe('convertBase64DerToPem', () => {
  it('wraps base64 DER in PEM headers', () => {
    const base64Der = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA';
    const pem = convertBase64DerToPem(base64Der);

    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
    expect(pem).toContain(base64Der);
  });
});

describe('convertPemToBase64Der', () => {
  it('converts a PEM certificate to base64 DER', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    const pem = await createSelfSignedCertificateFromJwk({ ...privateJwk, alg: 'ES256', kty: 'EC' });

    const base64Der = convertPemToBase64Der(pem);

    expect(base64Der).not.toContain('BEGIN CERTIFICATE');
    expect(base64Der.length).toBeGreaterThan(0);
  });
});

describe('createSelfSignedCertificateFromJwk', () => {
  it('creates a certificate whose public key verifies signatures from the same private key', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    const certificatePem = await createSelfSignedCertificateFromJwk({ ...privateJwk, alg: 'ES256', kty: 'EC' });
    const certificateKey = await importX509(certificatePem, 'ES256');

    const jwt = await new SignJWT({ sub: 'test-subject' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(jwtVerify(jwt, certificateKey)).resolves.toBeDefined();
  });
});
