import { webcrypto } from 'node:crypto';

import * as x509 from '@peculiar/x509';
import { X509Certificate } from '@peculiar/x509';
import { exportJWK, importX509, type JWK } from 'jose';

/** Parses an X.509 certificate and returns basic metadata
 * (issuer/subject, validity, serial number, PEM, and thumbprint)
 *
 * @param input - An object containing the certificate data as an ArrayBuffer
 * @returns An object with parsed certificate information such as issuer/subject names,
 * validity period, serial number, PEM, and thumbprint
 */
export const getCertificateData = async (input: { certificate: ArrayBuffer }) => {
  const certificate = new X509Certificate(input.certificate);
  const thumbprint = await certificate.getThumbprint(webcrypto);
  const thumbprintHex = Buffer.from(thumbprint).toString('hex');
  return {
    issuerName: certificate.issuerName.toString(),
    notAfter: certificate.notAfter,
    notBefore: certificate.notBefore,
    pem: certificate.toString(),
    serialNumber: certificate.serialNumber,
    subjectName: certificate.subjectName.toString(),
    thumbprint: thumbprintHex
  };
};

/** Extracts the public key from the leaf certificate in a certificate chain
 * and converts it to JWK format
 *
 * @param input - An object containing the algorithm and the certificate chain
 * @returns A JWK representation of the public key
 */
export const getCertificateChainPublicKey = async (input: { alg: string; certificateChain: readonly unknown[] }) => {
  const [leafCertificate] = input.certificateChain;
  if (leafCertificate === undefined) {
    throw new Error('x5c certificate not found');
  }
  if (typeof leafCertificate !== 'string') {
    throw new Error('Invalid x5c certificate format');
  }

  const key = await importX509(convertBase64DerToPem(leafCertificate), input.alg, {
    extractable: true
  });

  return await exportJWK(key);
};

/** Validates a certificate chain against a set of trusted root certificates,
 * ensuring the chain is properly ordered, and each certificate is valid and
 * signed by its issuer
 *
 * @param input - An object containing the current date, trusted certificates,
 * and the certificate chain to validate
 * @returns A promise that resolves if the certificate chain is valid, or
 * rejects with an error if invalid
 */
export const validateCertificateChain = async (input: {
  now?: Date;
  trustedCertificates: [ArrayBuffer, ...ArrayBuffer[]];
  x5chain: [ArrayBuffer, ...ArrayBuffer[]];
}) => {
  const { now, trustedCertificates, x5chain: certificateChain } = input;
  if (certificateChain.length === 0) {
    throw new Error('Certificate chain is empty');
  }

  const validationDate = now ?? new Date();
  const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0]);
  const parsedCertificates = certificateChain.map((c) => new x509.X509Certificate(c));

  const certificateChainBuilder = new x509.X509ChainBuilder({ certificates: parsedCertificates });
  const chain = await certificateChainBuilder.build(parsedLeafCertificate);

  let parsedChain = chain.map((c) => new x509.X509Certificate(c.rawData)).reverse();

  if (parsedChain.length !== certificateChain.length) {
    throw new Error('Could not parse the full chain. Likely due to incorrect ordering');
  }

  const parsedTrustedCertificates = trustedCertificates.map(
    (trustedCertificate) => new x509.X509Certificate(trustedCertificate)
  );

  const trustedCertificateIndex = parsedChain.findIndex((cert) =>
    parsedTrustedCertificates.some((tCert) => cert.equal(tCert))
  );

  if (trustedCertificateIndex === -1) {
    throw new Error('No trusted certificate was found while validating the X.509 chain');
  }

  parsedChain = parsedChain.slice(trustedCertificateIndex);

  for (let i = 1; i < parsedChain.length; i++) {
    const cert = parsedChain[i] as X509Certificate;
    const issuerCertificate = parsedChain[i - 1] as X509Certificate;
    await cert.verify({ date: validationDate, publicKey: issuerCertificate.publicKey });
  }
};

// Utility function to convert a base64 DER-encoded certificate to PEM format
export const convertBase64DerToPem = (certificate: string): string =>
  `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;

export const convertPemToBase64Der = (certificatePem: string): string =>
  Buffer.from(new X509Certificate(certificatePem).rawData).toString('base64');

export const createSelfSignedCertificateFromJwk = async (jwk: JWK): Promise<string> => {
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

  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    keys: { privateKey, publicKey },
    name: 'C=IT, O=ITW Conformance Tool, CN=Issuer Signing Certificate',
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(0x0080, true),
      await x509.SubjectKeyIdentifierExtension.create(publicKey)
    ]
  });

  return certificate.toString();
};

function stripPrivateKeyMaterial(jwk: JWK): JWK {
  const { d, key_ops, ...publicJwk } = jwk as JWK & { d?: string; key_ops?: string[] };
  void d;
  void key_ops;
  return publicJwk;
}
