import { isIP } from 'node:net';

import {
  BasicConstraintsExtension,
  Extension,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator
} from '@peculiar/x509';

import type { IacaChain, IacaChainParams, X5cCertParams } from '../types/types.js';

interface CertificateOptions {
  commonName: string;
  organizationName?: string;
  countryName?: string;
  notAfterDays: number;
  isCA?: boolean;
  keyUsageBits: number;
  altNames?: string[];
}

/** Generates a self-signed X.509 certificate using ECDSA P-256.
 *
 * @param options - Certificate options including subject, validity period, and extensions.
 * @returns An object containing the certificate and private key in PEM format.
 */
async function generateCertificate({
  commonName,
  organizationName = 'ITW Conformance Tool',
  countryName = 'IT',
  notAfterDays,
  isCA = false,
  keyUsageBits,
  altNames = []
}: CertificateOptions): Promise<{ certPem: string; keyPem: string }> {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setDate(notAfter.getDate() + notAfterDays);

  const name = `C=${countryName}, O=${organizationName}, CN=${commonName}`;

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

  const cert = await X509CertificateGenerator.createSelfSigned({
    keys: keyPair,
    name,
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions
  });

  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const b64 = Buffer.from(pkcs8).toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  const keyPem = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;

  return { certPem: cert.toString(), keyPem };
}

/** Generates and returns a self-signed IACA certificate chain.
 *
 * @param params - Optional parameters to customize the certificate subject.
 * @returns An object containing the certificate and private key in PEM format.
 */
export async function getIACAChain({
  commonName = 'IACA CA',
  countryName = 'IT',
  organizationName = 'Example Issuer'
}: IacaChainParams = {}): Promise<IacaChain> {
  const { certPem, keyPem } = await generateCertificate({
    commonName,
    countryName,
    organizationName,
    notAfterDays: 365 * 10,
    isCA: true,
    keyUsageBits: 0x0004 | 0x0002 | 0x0080 // keyCertSign | cRLSign | digitalSignature
  });

  return {
    certificate: certPem,
    privateKey: keyPem
  };
}

/** Generates a self-signed X.509 certificate for use in JWT x5c header (Relying Party).
 * The certificate is valid for 1 year.
 *
 * @param params - Optional parameters to customize the certificate subject.
 * @returns The certificate in PEM format as a string.
 */
export async function getX5cCert({
  commonName = 'Relying Party',
  organizationName = 'ITW Conformance Tool'
}: X5cCertParams = {}): Promise<string> {
  const { certPem } = await generateCertificate({
    commonName,
    organizationName,
    notAfterDays: 365,
    isCA: false,
    keyUsageBits: 0x80 // digitalSignature
  });

  return certPem;
}
