import { BasicConstraintsExtension, KeyUsagesExtension, X509Certificate } from '@peculiar/x509';
import { describe, expect, it } from 'vitest';

import { getX5cCert } from '../services/certificates.js';
import { generateEcPrivateJwk } from '../services/jwk.js';
import {
  convertBase64DerToPem,
  convertPemToBase64Der,
  createSelfSignedCertificateFromJwk,
  getCertificateChainPublicKey,
  getCertificateData,
  validateCertificateChain
} from '../services/x509.js';

describe('x509 service', () => {
  it('converts PEM to base64 DER and back preserving certificate bytes', async () => {
    const certPem = await getX5cCert();

    const base64Der = convertPemToBase64Der(certPem);
    const pemFromDer = convertBase64DerToPem(base64Der);

    expect(convertPemToBase64Der(pemFromDer)).toBe(base64Der);
  });

  it('extracts certificate data from raw certificate bytes', async () => {
    const certPem = await getX5cCert({
      commonName: 'RP CN',
      organizationName: 'RP Org'
    });
    const cert = new X509Certificate(certPem);

    const data = await getCertificateData({ certificate: cert.rawData });

    expect(data.subjectName).toContain('CN=RP CN');
    expect(data.issuerName).toBe(data.subjectName);
    expect(data.serialNumber).toBeTruthy();
    expect(data.thumbprint).toMatch(/^[a-f0-9]{40}$/);
    expect(data.notAfter.getTime()).toBeGreaterThan(data.notBefore.getTime());
    expect(data.pem).toContain('BEGIN CERTIFICATE');
  });

  it('extracts the public JWK from an x5c certificate chain', async () => {
    const certPem = await getX5cCert();
    const leafCertificateDerB64 = convertPemToBase64Der(certPem);

    const publicJwk = await getCertificateChainPublicKey({
      alg: 'ES256',
      certificateChain: [leafCertificateDerB64]
    });

    expect(publicJwk).toMatchObject({
      kty: 'EC',
      crv: 'P-256'
    });
    expect(publicJwk).not.toHaveProperty('d');
  });

  it('rejects malformed x5c leaf certificate values', async () => {
    await expect(
      getCertificateChainPublicKey({
        alg: 'ES256',
        certificateChain: []
      })
    ).rejects.toThrow('x5c certificate not found');

    await expect(
      getCertificateChainPublicKey({
        alg: 'ES256',
        certificateChain: [123]
      })
    ).rejects.toThrow('Invalid x5c certificate format');

    await expect(
      getCertificateChainPublicKey({
        alg: 'ES256',
        certificateChain: ['not-a-certificate']
      })
    ).rejects.toThrow();
  });

  it('fails when validateCertificateChain receives an empty chain at runtime', async () => {
    const certPem = await getX5cCert();
    const cert = new X509Certificate(certPem);

    await expect(
      validateCertificateChain({
        trustedCertificates: [cert.rawData],
        x5chain: [] as unknown as [ArrayBuffer, ...ArrayBuffer[]]
      })
    ).rejects.toThrow('Certificate chain is empty');
  });

  it('validates a trusted self-signed certificate chain', async () => {
    const certPem = await getX5cCert();
    const cert = new X509Certificate(certPem);

    await expect(
      validateCertificateChain({
        trustedCertificates: [cert.rawData],
        x5chain: [cert.rawData]
      })
    ).resolves.toBeUndefined();
  });

  it('fails when the certificate chain does not include a trusted certificate', async () => {
    const cert = new X509Certificate(await getX5cCert({ commonName: 'leaf' }));
    const otherTrusted = new X509Certificate(await getX5cCert({ commonName: 'other-trust-anchor' }));

    await expect(
      validateCertificateChain({
        trustedCertificates: [otherTrusted.rawData],
        x5chain: [cert.rawData]
      })
    ).rejects.toThrow('No trusted certificate was found while validating the X.509 chain');
  });

  it('fails when chain ordering does not allow full chain parsing', async () => {
    const cert1 = new X509Certificate(await getX5cCert({ commonName: 'first' }));
    const cert2 = new X509Certificate(await getX5cCert({ commonName: 'second' }));

    await expect(
      validateCertificateChain({
        trustedCertificates: [cert1.rawData],
        x5chain: [cert1.rawData, cert2.rawData]
      })
    ).rejects.toThrow('Could not parse the full chain. Likely due to incorrect ordering');
  });

  it('creates a self-signed certificate from an EC private JWK', async () => {
    const jwks = generateEcPrivateJwk({
      kid: 'issuer-signing-key',
      alg: 'ES256',
      use: 'sig',
      keyOps: ['sign']
    });

    const certificatePem = await createSelfSignedCertificateFromJwk(jwks.keys[0]);
    const certificate = new X509Certificate(certificatePem);

    expect(certificate.subject).toContain('CN=Issuer Signing Certificate');
    expect(certificate.issuer).toBe(certificate.subject);

    const basicConstraints = certificate.getExtension(BasicConstraintsExtension);
    const keyUsages = certificate.getExtension(KeyUsagesExtension);

    expect(basicConstraints).toBeTruthy();
    expect(basicConstraints?.ca).toBe(false);
    expect(keyUsages).toBeTruthy();
  });

  it('fails to create a certificate when private key material is missing from JWK', async () => {
    const jwks = generateEcPrivateJwk({
      kid: 'issuer-signing-key',
      alg: 'ES256',
      use: 'sig',
      keyOps: ['sign']
    });

    const privateJwk = jwks.keys[0] as Record<string, unknown>;
    const { d: _removedD, ...publicJwkOnly } = privateJwk;

    await expect(createSelfSignedCertificateFromJwk(publicJwkOnly)).rejects.toThrow();
  });
});
