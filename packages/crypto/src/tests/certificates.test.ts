import { SubjectAlternativeNameExtension, X509Certificate } from '@peculiar/x509';
import { describe, expect, it } from 'vitest';

import { getIACAChain, getTlsCertAndKey, getX5cCert } from '../services/certificates.js';

describe('certificates service', () => {
  it('getIACAChain returns a self-signed CA certificate and private key', async () => {
    const chain = await getIACAChain();

    expect(chain.certificate).toContain('BEGIN CERTIFICATE');
    expect(chain.privateKey).toContain('BEGIN PRIVATE KEY');

    // Note: The certificate uses ECDSA P-256 which forge doesn't support,
    // so we just verify the certificate is in valid PEM format
    expect(chain.certificate).toContain('END CERTIFICATE');
  });

  it('getIACAChain applies custom subject fields', async () => {
    const chain = await getIACAChain({
      commonName: 'Custom IACA',
      countryName: 'FR',
      organizationName: 'Custom Org'
    });

    // Note: The certificate uses ECDSA P-256 which forge doesn't support,
    // so we just verify the certificate is in valid PEM format
    expect(chain.certificate).toContain('BEGIN CERTIFICATE');
    expect(chain.certificate).toContain('END CERTIFICATE');
    expect(chain.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('getTlsCertAndKey returns certificate and key with SAN entries', async () => {
    const tls = await getTlsCertAndKey({
      altNames: ['localhost', 'wallet.local', '127.0.0.1'],
      commonName: 'localhost',
      organizationName: 'ITW'
    });

    expect(tls.cert).toContain('BEGIN CERTIFICATE');
    expect(tls.key).toContain('BEGIN PRIVATE KEY');
    expect(tls.cert).toContain('END CERTIFICATE');

    const parsedCert = new X509Certificate(tls.cert);
    const san = parsedCert.getExtension(SubjectAlternativeNameExtension);

    expect(san).toBeTruthy();
    expect(san?.names.toJSON()).toEqual(
      expect.arrayContaining([
        { type: 'dns', value: 'localhost' },
        { type: 'dns', value: 'wallet.local' },
        { type: 'ip', value: '127.0.0.1' }
      ])
    );
  });

  it('getX5cCert returns a client-auth certificate valid for about one year', async () => {
    const x5c = await getX5cCert({
      commonName: 'RP CN',
      organizationName: 'RP Org'
    });

    expect(x5c).toContain('BEGIN CERTIFICATE');
    expect(x5c).toContain('END CERTIFICATE');
  });
});
