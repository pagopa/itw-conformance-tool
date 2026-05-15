import { describe, expect, it } from 'vitest';

import { convertBase64DerToPem } from '../../utils/x509.js';

describe('convertBase64DerToPem', () => {
  it('wraps base64 DER in PEM headers', () => {
    const base64Der = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA';
    const pem = convertBase64DerToPem(base64Der);

    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
    expect(pem).toContain(base64Der);
  });
});
