import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';

import * as x509 from '@peculiar/x509';

const CERTIFICATE_SIGNING_ALGORITHM = {
  hash: 'SHA-256',
  name: 'ECDSA'
} as const;

const KEY_PAIR_ALGORITHM = {
  name: 'ECDSA',
  namedCurve: 'P-256'
} as const;

const CERTIFICATE_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000;
export interface RuntimeHttpsOptions {
  ca: string;
  cert: string;
  key: string;
}

function encodePem(label: string, data: ArrayBuffer): string {
  const base64 = Buffer.from(data).toString('base64');
  const body = base64.match(/.{1,64}/g)?.join('\n') ?? '';

  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export async function createHttpsOptions(): Promise<RuntimeHttpsOptions> {
  const now = new Date();
  const notAfter = new Date(now.getTime() + CERTIFICATE_VALIDITY_MS);

  const caKeys = await webcrypto.subtle.generateKey(KEY_PAIR_ALGORITHM, true, ['sign', 'verify']);
  const serverKeys = await webcrypto.subtle.generateKey(KEY_PAIR_ALGORITHM, true, ['sign', 'verify']);

  const caCertificate = await x509.X509CertificateGenerator.createSelfSigned(
    {
      keys: caKeys,
      name: 'CN=IT Wallet Conformance Tool Local CA',
      notAfter,
      notBefore: now,
      signingAlgorithm: CERTIFICATE_SIGNING_ALGORITHM,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)
      ]
    },
    webcrypto
  );

  const certificate = await x509.X509CertificateGenerator.create(
    {
      issuer: caCertificate.subject,
      notAfter,
      notBefore: now,
      publicKey: serverKeys.publicKey,
      signingAlgorithm: CERTIFICATE_SIGNING_ALGORITHM,
      signingKey: caKeys.privateKey,
      subject: 'CN=localhost',
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], true),
        new x509.SubjectAlternativeNameExtension([
          { type: 'dns', value: 'localhost' },
          { type: 'ip', value: '127.0.0.1' },
          { type: 'ip', value: '::1' }
        ]),
        await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
        await x509.SubjectKeyIdentifierExtension.create(serverKeys.publicKey)
      ]
    },
    webcrypto
  );

  const key = await webcrypto.subtle.exportKey('pkcs8', serverKeys.privateKey);

  return {
    ca: caCertificate.toString('pem'),
    cert: certificate.toString('pem'),
    key: encodePem('PRIVATE KEY', key)
  };
}
