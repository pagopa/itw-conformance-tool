import { createPrivateKey, createPublicKey } from 'node:crypto';

import forge from 'node-forge';

import type {
  CertificateParams,
  ForgeAttribute,
  GenerateKeyPairResult,
  IacaChain,
  IacaChainParams,
  TlsCertAndKey,
  TlsCertParams,
  X5cCertParams
} from '../types/types.js';

/** Generates an RSA key pair and returns the private key
 * in both PEM and JWK formats.
 *
 * @returns An object containing the private key in PEM
 * format and as a JWK record.
 */
function generateRsaKeyPair(): GenerateKeyPairResult {
  const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(publicKey);

  return {
    privateKey,
    publicKey,
    privateKeyPem,
    publicKeyPem,
    privateJwk: createPrivateKey(privateKeyPem).export({ format: 'jwk' }),
    publicJwk: createPublicKey(publicKeyPem).export({ format: 'jwk' })
  };
}

/** Creates and signs an X.509 certificate.
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

/** Generates and returns a self-signed IACA certificate chain.
 *
 * @param params - Optional parameters to customize the certificate
 * subject and serial number.
 * @returns An object containing the certificate and private key
 * in PEM format as separate strings.
 */
export function getIACAChain({
  commonName = 'IACA CA',
  countryName = 'IT',
  organizationName = 'Example Issuer',
  serialNumber = '01'
}: IacaChainParams = {}): IacaChain {
  const iacaKeys = generateRsaKeyPair();
  const iacaSubject: ForgeAttribute[] = [
    { name: 'commonName', value: commonName },
    { name: 'countryName', value: countryName },
    { name: 'organizationName', value: organizationName }
  ];

  const iacaCert = createCertificate({
    subject: iacaSubject,
    issuer: iacaSubject,
    publicKey: iacaKeys.publicKey,
    issuerPrivateKey: iacaKeys.privateKey,
    serialNumber,
    isCA: true
  });

  return {
    certificate: forge.pki.certificateToPem(iacaCert),
    privateKey: forge.pki.privateKeyToPem(iacaKeys.privateKey)
  };
}

/** Generates a self-signed TLS certificate and private key for localhost.
 * The certificate is valid for 825 days (the maximum accepted by macOS).
 *
 * @param params - Optional parameters to customize the certificate subject and alternative names.
 * @returns An object containing the certificate and private key in PEM format as separate strings.
 */
export function getTlsCertAndKey({
  commonName = 'localhost',
  organizationName = 'ITW Conformance Tool',
  altNames = ['localhost']
}: TlsCertParams = {}): TlsCertAndKey {
  const keys = generateRsaKeyPair();

  const attrs: ForgeAttribute[] = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organizationName }
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
    { name: 'subjectAltName', altNames: altNames.map((value) => ({ type: 2, value })) }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey)
  };
}

/** Generates a self-signed X.509 certificate for use in JWT x5c header (Relying Party).
 * The certificate is valid for 1 year.
 *
 * @param params - Optional parameters to customize the certificate subject.
 * @returns The certificate in PEM format as a string.
 */
export function getX5cCert({
  commonName = 'Relying Party',
  organizationName = 'ITW Conformance Tool'
}: X5cCertParams = {}): string {
  const keys = generateRsaKeyPair();

  const attrs: ForgeAttribute[] = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organizationName }
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
