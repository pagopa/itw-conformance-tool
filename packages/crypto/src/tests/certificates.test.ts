import forge from 'node-forge';
import { describe, expect, it } from 'vitest';

import { getIACAChain, getTlsCertAndKey, getX5cCert } from '../services/certificates.js';

type BasicConstraintsExt = { cA?: boolean };
type SubjectAltNameExt = { altNames?: Array<{ value?: string }> };
type ExtKeyUsageExt = { clientAuth?: boolean };

function validityDays(cert: forge.pki.Certificate): number {
  const millis = cert.validity.notAfter.getTime() - cert.validity.notBefore.getTime();
  return millis / (24 * 60 * 60 * 1000);
}

describe('certificates service', () => {
  it('getIACAChain returns a self-signed CA certificate and private key', () => {
    const chain = getIACAChain();

    expect(chain.certificate).toContain('BEGIN CERTIFICATE');
    expect(chain.privateKey).toContain('BEGIN RSA PRIVATE KEY');

    const cert = forge.pki.certificateFromPem(chain.certificate);
    const subjectCn = cert.subject.getField('CN')?.value;
    const issuerCn = cert.issuer.getField('CN')?.value;
    const basicConstraints = cert.getExtension('basicConstraints') as BasicConstraintsExt | undefined;

    expect(subjectCn).toBe('IACA CA');
    expect(issuerCn).toBe('IACA CA');
    expect(basicConstraints?.cA).toBe(true);
  });

  it('getIACAChain applies custom subject fields', () => {
    const chain = getIACAChain({
      commonName: 'Custom IACA',
      countryName: 'FR',
      organizationName: 'Custom Org',
      serialNumber: '10'
    });

    const cert = forge.pki.certificateFromPem(chain.certificate);

    expect(cert.subject.getField('CN')?.value).toBe('Custom IACA');
    expect(cert.subject.getField('C')?.value).toBe('FR');
    expect(cert.subject.getField('O')?.value).toBe('Custom Org');
    expect(cert.serialNumber).toBe('10');
  });

  it('getTlsCertAndKey returns certificate and key with SAN entries', () => {
    const tls = getTlsCertAndKey({
      altNames: ['localhost', 'wallet.local'],
      commonName: 'localhost',
      organizationName: 'ITW'
    });

    expect(tls.cert).toContain('BEGIN CERTIFICATE');
    expect(tls.key).toContain('BEGIN RSA PRIVATE KEY');

    const cert = forge.pki.certificateFromPem(tls.cert);
    const san = cert.getExtension('subjectAltName') as SubjectAltNameExt | undefined;

    expect(cert.subject.getField('CN')?.value).toBe('localhost');
    expect(cert.subject.getField('O')?.value).toBe('ITW');
    expect(san?.altNames?.map((entry: { value?: string }) => entry.value)).toEqual(['localhost', 'wallet.local']);

    const days = validityDays(cert);
    expect(days).toBeGreaterThan(800);
    expect(days).toBeLessThanOrEqual(825);
  });

  it('getX5cCert returns a client-auth certificate valid for about one year', () => {
    const x5c = getX5cCert({
      commonName: 'RP CN',
      organizationName: 'RP Org'
    });

    expect(x5c).toContain('BEGIN CERTIFICATE');

    const cert = forge.pki.certificateFromPem(x5c);
    const extKeyUsage = cert.getExtension('extKeyUsage') as ExtKeyUsageExt | undefined;

    expect(cert.subject.getField('CN')?.value).toBe('RP CN');
    expect(cert.subject.getField('O')?.value).toBe('RP Org');
    expect(extKeyUsage?.clientAuth).toBe(true);

    const days = validityDays(cert);
    expect(days).toBeGreaterThan(360);
    expect(days).toBeLessThanOrEqual(365);
  });
});
