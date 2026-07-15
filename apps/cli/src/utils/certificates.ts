import { webcrypto } from 'node:crypto';
import { isIP } from 'node:net';

import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateGenerator
} from '@peculiar/x509';

type CertificateOptions = {
  altNames?: string[];
  commonName: string;
  countryName?: string;
  isCA?: boolean;
  keyUsageBits: number;
  notAfterDays: number;
  organizationName?: string;
};

type IacaChainParams = {
  commonName?: string;
  countryName?: string;
  organizationName?: string;
};

type SelfSignedCertificateFromJwkOptions = {
  commonName?: string;
  extendedKeyUsages?: string[];
  organizationalUnitName?: string;
  organizationName?: string;
};

type Jwk = Record<string, unknown>;
type Jwks = { keys: Jwk[] };

type IssuerChainCertificateOptions = {
  commonName?: string;
  organizationName?: string;
};

type IssuerCertificateOptions = {
  altNames?: string[];
  organizationName?: string;
};

async function generateCertificate({
  altNames = [],
  commonName,
  countryName = 'IT',
  isCA = false,
  keyUsageBits,
  notAfterDays,
  organizationName = 'ITW Conformance Tool'
}: CertificateOptions): Promise<{ certPem: string; keyPem: string }> {
  const keyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setDate(notAfter.getDate() + notAfterDays);

  const extensions: Extension[] = [
    new BasicConstraintsExtension(isCA, isCA ? 0 : undefined, true),
    new KeyUsagesExtension(keyUsageBits, true),
    await SubjectKeyIdentifierExtension.create(keyPair.publicKey)
  ];

  if (!isCA) {
    const uniqueAltNames = [...new Set([commonName, ...altNames])];
    extensions.push(
      new SubjectAlternativeNameExtension(
        uniqueAltNames.map((name) => ({
          type: isIP(name) ? 'ip' : 'dns',
          value: name
        }))
      )
    );
  }

  const certificate = await X509CertificateGenerator.createSelfSigned({
    keys: keyPair,
    name: `C=${countryName}, O=${organizationName}, CN=${commonName}`,
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions
  });

  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const b64 = Buffer.from(pkcs8).toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [b64];

  return {
    certPem: certificate.toString(),
    keyPem: `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`
  };
}

export async function getIACAChain({
  commonName = 'IACA CA',
  countryName = 'IT',
  organizationName = 'Example Issuer'
}: IacaChainParams = {}): Promise<{ certificate: string; privateKey: string }> {
  const { certPem, keyPem } = await generateCertificate({
    commonName,
    countryName,
    organizationName,
    notAfterDays: 365 * 10,
    isCA: true,
    keyUsageBits: 0x0004 | 0x0002 | 0x0080
  });

  return {
    certificate: certPem,
    privateKey: keyPem
  };
}

function stripPrivateKeyMaterial(jwk: Record<string, unknown>): Record<string, unknown> {
  const {
    d: _d,
    key_ops: _keyOps,
    ...publicJwk
  } = jwk as Record<string, unknown> & {
    d?: string;
    key_ops?: string[];
  };
  void _d;
  void _keyOps;
  return publicJwk;
}

/** Imports an EC P-256 private JWK as a Web Crypto private/public key pair.
 *
 * @param jwk - The private EC JWK to import.
 * @returns The imported private and public `CryptoKey`s.
 */
async function importEcKeyPairFromJwk(
  jwk: Jwk
): Promise<{ privateKey: webcrypto.CryptoKey; publicKey: webcrypto.CryptoKey }> {
  const publicJwk = stripPrivateKeyMaterial(jwk);

  const publicKey = await webcrypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'verify'
  ]);
  const privateKey = await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign'
  ]);

  return { privateKey, publicKey };
}

/** Selects the sole private ES256 signing key (`kty=EC`, `alg=ES256`, `use=sig`)
 * from a JWKS, failing clearly when it is absent or ambiguous.
 *
 * `issuer/jwks.json` also contains an ECDH-ES encryption key, so certificate
 * generation must not silently pick the wrong key.
 *
 * @param jwks - The JWKS to search.
 * @returns The private ES256 signing JWK.
 */
export function selectEs256SigningJwk(jwks: Jwks): Jwk {
  const candidates = jwks.keys.filter(
    (key) => key.kty === 'EC' && key.alg === 'ES256' && key.use === 'sig' && typeof key.d === 'string'
  );

  if (candidates.length === 0) {
    throw new Error('No private ES256 signing key (kty=EC, alg=ES256, use=sig) found in JWKS');
  }
  if (candidates.length > 1) {
    throw new Error('Multiple private ES256 signing keys found in JWKS; expected exactly one');
  }

  return candidates[0];
}

export async function createSelfSignedCertificateFromJwk(
  jwk: Record<string, unknown>,
  {
    commonName = 'Issuer Signing Certificate',
    extendedKeyUsages = [],
    organizationalUnitName,
    organizationName = 'ITW Conformance Tool'
  }: SelfSignedCertificateFromJwkOptions = {}
): Promise<string> {
  const { privateKey, publicKey } = await importEcKeyPairFromJwk(jwk);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  const extensions: Extension[] = [
    new BasicConstraintsExtension(false, undefined, true),
    new KeyUsagesExtension(0x0080, true),
    await SubjectKeyIdentifierExtension.create(publicKey)
  ];
  if (extendedKeyUsages.length > 0) {
    extensions.splice(2, 0, new ExtendedKeyUsageExtension(extendedKeyUsages));
  }

  const organizationalUnit = organizationalUnitName ? `, OU=${organizationalUnitName}` : '';
  const certificate = await X509CertificateGenerator.createSelfSigned({
    keys: { privateKey, publicKey },
    name: `C=IT, O=${organizationName}${organizationalUnit}, CN=${commonName}`,
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions
  });

  return certificate.toString();
}

/** Generates the Trust Anchor federation certificate from its existing signing JWK. */
export async function createTrustAnchorCertificateFromJwk(
  jwk: Record<string, unknown>,
  commonName: string
): Promise<string> {
  return createSelfSignedCertificateFromJwk(jwk, {
    commonName,
    extendedKeyUsages: [ExtendedKeyUsage.serverAuth, ExtendedKeyUsage.clientAuth],
    organizationalUnitName: 'Trust Anchor'
  });
}

/** Creates the issuer intermediate CA certificate (`issuer/intermediate-cert.pem`).
 *
 * Its subject public key comes from the intermediate CA JWK, while its
 * issuer DN and signature come from the trust-anchor federation key and
 * certificate, chaining it to `trust-anchor/federation-cert.pem`.
 *
 * @param intermediateJwk - The intermediate CA's private ES256 JWK; its public key becomes the certificate's subject key.
 * @param trustAnchorJwk - The trust-anchor federation private ES256 JWK, used to sign the certificate.
 * @param trustAnchorCertificatePem - The trust-anchor federation certificate, used for the issuer DN.
 * @param options - Optional subject overrides.
 * @returns A PEM-encoded intermediate CA certificate.
 */
export async function createIntermediateCertificateFromJwk(
  intermediateJwk: Jwk,
  trustAnchorJwk: Jwk,
  trustAnchorCertificatePem: string,
  {
    commonName = 'Issuer Intermediate CA',
    organizationName = 'ITW Conformance Tool'
  }: IssuerChainCertificateOptions = {}
): Promise<string> {
  const { publicKey: intermediatePublicKey } = await importEcKeyPairFromJwk(intermediateJwk);
  const { privateKey: trustAnchorPrivateKey, publicKey: trustAnchorPublicKey } =
    await importEcKeyPairFromJwk(trustAnchorJwk);

  const trustAnchorCertificate = new X509Certificate(trustAnchorCertificatePem);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 5);

  const certificate = await X509CertificateGenerator.create({
    issuer: trustAnchorCertificate.subject,
    subject: `C=IT, O=${organizationName}, CN=${commonName}`,
    notBefore: now,
    notAfter,
    publicKey: intermediatePublicKey,
    signingKey: trustAnchorPrivateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      await SubjectKeyIdentifierExtension.create(intermediatePublicKey),
      await AuthorityKeyIdentifierExtension.create(trustAnchorPublicKey)
    ]
  });

  return certificate.toString();
}

/** Creates the issuer leaf certificate (`issuer/cert.pem`).
 *
 * Its subject public key comes from the ES256 signing key in
 * `issuer/jwks.json`, while its issuer DN and signature come from the
 * intermediate CA key/certificate, chaining it through
 * `issuer/intermediate-cert.pem`.
 *
 * @param issuerSigningJwk - The issuer's private ES256 signing JWK; its public key becomes the certificate's subject key.
 * @param intermediateJwk - The intermediate CA's private ES256 JWK, used to sign the certificate.
 * @param intermediateCertificatePem - The intermediate CA certificate, used for the issuer DN.
 * @param credentialIssuerUrl - The configured credential-issuer URL, used to derive the subject CN and SAN.
 * @param options - Optional subject overrides.
 * @returns A PEM-encoded issuer leaf certificate.
 */
export async function createIssuerCertificateFromJwk(
  issuerSigningJwk: Jwk,
  intermediateJwk: Jwk,
  intermediateCertificatePem: string,
  credentialIssuerUrl: string,
  { altNames = [], organizationName = 'ITW Conformance Tool' }: IssuerCertificateOptions = {}
): Promise<string> {
  const { publicKey: issuerPublicKey } = await importEcKeyPairFromJwk(issuerSigningJwk);
  const { privateKey: intermediatePrivateKey, publicKey: intermediatePublicKey } =
    await importEcKeyPairFromJwk(intermediateJwk);

  const intermediateCertificate = new X509Certificate(intermediateCertificatePem);
  const commonName = new URL(credentialIssuerUrl).hostname;
  const uniqueAltNames = [...new Set([commonName, ...altNames])];

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  const certificate = await X509CertificateGenerator.create({
    issuer: intermediateCertificate.subject,
    subject: `C=IT, O=${organizationName}, CN=${commonName}`,
    notBefore: now,
    notAfter,
    publicKey: issuerPublicKey,
    signingKey: intermediatePrivateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new SubjectAlternativeNameExtension(
        uniqueAltNames.map((name) => ({ type: isIP(name) ? 'ip' : 'dns', value: name }))
      ),
      await SubjectKeyIdentifierExtension.create(issuerPublicKey),
      await AuthorityKeyIdentifierExtension.create(intermediatePublicKey)
    ]
  });

  return certificate.toString();
}
