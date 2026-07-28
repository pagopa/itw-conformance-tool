import { X509Certificate } from 'node:crypto';

import { expect } from 'vitest';

export function certificateFromBase64Der(certificate: string, description: string): X509Certificate {
  try {
    return new X509Certificate(Buffer.from(certificate, 'base64'));
  } catch (error) {
    throw new Error(
      `${description} must be a valid base64 DER-encoded X.509 certificate. ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

export function trustAnchorCertificateFromConfig(certificate: string): X509Certificate {
  const normalizedCertificate = certificate.trim().replaceAll('\\n', '\n');
  if (normalizedCertificate.length === 0) {
    throw new Error('global.trust_anchor_certificate must be configured to validate the Wallet Attestation x5c chain');
  }

  try {
    if (normalizedCertificate.includes('-----BEGIN CERTIFICATE-----')) {
      return new X509Certificate(normalizedCertificate);
    }

    return certificateFromBase64Der(normalizedCertificate, 'global.trust_anchor_certificate');
  } catch (error) {
    throw new Error(
      `global.trust_anchor_certificate must contain a valid PEM or base64 DER X.509 certificate. ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

export function expectCertificateValidAt(
  certificate: X509Certificate,
  validationDate: Date,
  description: string
): void {
  expect(validationDate.getTime(), `${description} should be within its X.509 validity period`).toBeGreaterThanOrEqual(
    certificate.validFromDate.getTime()
  );
  expect(validationDate.getTime(), `${description} should be within its X.509 validity period`).toBeLessThanOrEqual(
    certificate.validToDate.getTime()
  );
}

export function expectCertificateIssuedBy(
  certificate: X509Certificate,
  issuerCertificate: X509Certificate,
  description: string
): void {
  expect(certificate.issuer, `${description} issuer DN should match the issuing certificate subject DN`).toBe(
    issuerCertificate.subject
  );
  expect(
    certificate.verify(issuerCertificate.publicKey),
    `${description} signature should verify with the issuing certificate public key`
  ).toBe(true);
}
