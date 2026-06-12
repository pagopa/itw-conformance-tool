import forge from 'node-forge';

import type { CertificateParams, ForgeAttribute, IacaChain, TlsCertAndKey } from '../types/types.js';

/**
 * Generates a 2048-bit RSA key pair using node-forge.
 */
function generateKeyPair(): forge.pki.rsa.KeyPair {
  return forge.pki.rsa.generateKeyPair(2048);
}

/**
 * Creates and signs an X.509 certificate.
 *
 * @param params - Certificate parameters including subject, issuer, keys, serial number, and CA flag.
 * @returns The signed forge certificate object.
 */
function createCertificate({
  subject,
  issuer,
  publicKey,
  issuerPrivateKey,
  serialNumber,
  isCA = false
}: CertificateParams) {
  const cert = forge.pki.createCertificate();

  cert.publicKey = publicKey;
  cert.serialNumber = serialNumber;

  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  cert.setSubject(subject);
  cert.setIssuer(issuer);

  const extensions = [
    {
      name: 'basicConstraints',
      cA: isCA,
      pathLenConstraint: isCA ? 0 : undefined
    },
    {
      name: 'keyUsage',
      keyCertSign: isCA,
      digitalSignature: true,
      cRLSign: isCA
    },
    {
      name: 'subjectKeyIdentifier'
    }
  ];

  cert.setExtensions(extensions);

  cert.sign(issuerPrivateKey, forge.md.sha256.create());

  return cert;
}

/**
 * Builds a self-signed IACA root certificate and returns it with its private key in PEM format.
 */
function buildIacaChain(): IacaChain {
  const iacaKeys = generateKeyPair();
  const iacaSubject: ForgeAttribute[] = [
    { name: 'commonName', value: 'IACA CA' },
    { name: 'countryName', value: 'IT' },
    { name: 'organizationName', value: 'Example Issuer' }
  ];

  const iacaCert = createCertificate({
    subject: iacaSubject,
    issuer: iacaSubject,
    publicKey: iacaKeys.publicKey,
    issuerPrivateKey: iacaKeys.privateKey,
    serialNumber: '01',
    isCA: true
  });

  return {
    certificate: forge.pki.certificateToPem(iacaCert),
    privateKey: forge.pki.privateKeyToPem(iacaKeys.privateKey)
  };
}

/**
 * Generates and returns a self-signed IACA certificate chain.
 */
export function getIACAChain(): IacaChain {
  return buildIacaChain();
}

/**
 * Generates a self-signed TLS certificate and private key for localhost.
 * The certificate is valid for 825 days (the maximum accepted by macOS).
 *
 * @returns An object containing the certificate and private key in PEM format as separate strings.
 */
export function getTlsCertAndKey(): TlsCertAndKey {
  const keys = generateKeyPair();

  const attrs: ForgeAttribute[] = [
    { name: 'commonName', value: 'localhost' },
    { name: 'organizationName', value: 'ITW Conformance Tool' }
  ];

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + 825 * 24 * 60 * 60 * 1000);

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectKeyIdentifier' },
    { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }] }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey)
  };
}

/**
 * Generates a self-signed X.509 certificate for use in JWT x5c header (Relying Party).
 * The certificate is valid for 1 year.
 *
 * @returns The certificate in PEM format as a string.
 */
export function getX5cCert(): string {
  const keys = generateKeyPair();

  const attrs: ForgeAttribute[] = [
    { name: 'commonName', value: 'Relying Party' },
    { name: 'organizationName', value: 'ITW Conformance Tool' }
  ];

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectKeyIdentifier' }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return forge.pki.certificateToPem(cert);
}
