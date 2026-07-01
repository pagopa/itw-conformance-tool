import { webcrypto } from 'node:crypto';
import { isIP } from 'node:net';

import {
  BasicConstraintsExtension,
  Extension,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
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

type TlsCertParams = {
  altNames?: string[];
  commonName?: string;
  organizationName?: string;
};

type IacaChainParams = {
  commonName?: string;
  countryName?: string;
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

export async function getTlsCertAndKey({
  altNames = [],
  commonName = 'localhost',
  organizationName = 'ITW Conformance Tool'
}: TlsCertParams = {}): Promise<{ cert: string; key: string }> {
  const { certPem, keyPem } = await generateCertificate({
    altNames,
    commonName,
    organizationName,
    notAfterDays: 825,
    isCA: false,
    keyUsageBits: 0x01 // digitalSignature (ECDSA TLS)
  });

  return {
    cert: certPem,
    key: keyPem
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

export async function createSelfSignedCertificateFromJwk(jwk: Record<string, unknown>): Promise<string> {
  const publicJwk = stripPrivateKeyMaterial(jwk);

  const publicKey = await webcrypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'verify'
  ]);
  const privateKey = await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign'
  ]);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  const certificate = await X509CertificateGenerator.createSelfSigned({
    keys: { privateKey, publicKey },
    name: 'C=IT, O=ITW Conformance Tool, CN=Issuer Signing Certificate',
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(0x0080, true),
      await SubjectKeyIdentifierExtension.create(publicKey)
    ]
  });

  return certificate.toString();
}
