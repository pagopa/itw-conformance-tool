import { generateKeyPairSync } from 'node:crypto';

import forge from 'node-forge';

// Types
type ForgeAttribute = { name: string; value: string } | { shortName: string; value: string };

type KeyUse = 'sig' | 'enc';

type JwkRecord = Record<string, unknown>;

// Interfaces
interface KeyDescriptor {
  kid: string;
  use: KeyUse;
}

interface JwkDescriptor {
  kid: string;
  use: KeyUse;
  alg: 'ES256' | 'ECDH-ES';
  keyOps: string[];
}

interface JwkSet {
  keys: JwkRecord[];
}

interface IacaChain {
  certificate: string;
  privateKey: string;
}

interface CertificateParams {
  subject: ForgeAttribute[];
  issuer: ForgeAttribute[];
  publicKey: forge.pki.rsa.PublicKey;
  issuerPrivateKey: forge.pki.rsa.PrivateKey;
  serialNumber: string;
  isCA?: boolean;
}

/** Serializes a value to a formatted JSON string. */
function toJSONString(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

/** Generates a 2048-bit RSA key pair, returning the private key in both PEM and JWK formats. */
function generateRsaKeyPair(): { privateKeyPem: string; privateJwk: JwkRecord } {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001
  });

  const privateJwk = privateKey.export({ format: 'jwk' }) as JwkRecord;
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

  return { privateKeyPem, privateJwk };
}

/** Generates a JWK Set containing a single RSA signing key.
 *
 * @param descriptor - Key identifier and intended use.
 * @returns A JSON string representing the JWK Set.
 */
function generateSigningJwks(descriptor: KeyDescriptor): string {
  const { privateJwk } = generateRsaKeyPair();
  const jwks: JwkSet = {
    keys: [
      {
        ...privateJwk,
        kid: descriptor.kid,
        alg: 'RS256',
        use: descriptor.use,
        key_ops: descriptor.use === 'sig' ? ['sign'] : ['encrypt']
      }
    ]
  };

  return toJSONString(jwks);
}

/** Generates an EC P-256 private key in JWK format.
 *
 * @param descriptor - Key metadata including kid, alg, use, and key_ops.
 * @returns A JSON string representing the private JWK.
 */
function generateEcPrivateJwk(descriptor: JwkDescriptor): string {
  const { privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  const privateJwk = privateKey.export({ format: 'jwk' }) as JwkRecord;

  return toJSONString({
    ...privateJwk,
    kid: descriptor.kid,
    alg: descriptor.alg,
    use: descriptor.use,
    key_ops: descriptor.keyOps
  });
}

/** Generates and returns a JWK Set containing the issuer RSA signing key. */
export function getSigningKeys(): string {
  return generateSigningJwks({ kid: 'issuer-signing-key', use: 'sig' });
}

/** Generates and returns an EC P-256 private key JWK for authentication request signing. */
export function getAuthRequestKey(): string {
  return generateEcPrivateJwk({
    kid: 'auth-request-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

/** Generates and returns an EC P-256 private key JWK for authentication response decryption. */
export function getAuthResponseKey(): string {
  return generateEcPrivateJwk({
    kid: 'auth-response-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['decrypt']
  });
}

/** Generates a 2048-bit RSA key pair using node-forge. */
function generateKeyPair(): forge.pki.rsa.KeyPair {
  return forge.pki.rsa.generateKeyPair(2048);
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

/** Builds a self-signed IACA root certificate and returns it with its private key in PEM format. */
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

/** Generates and returns a self-signed IACA certificate chain. */
export function getIACAChain(): IacaChain {
  return buildIacaChain();
}
