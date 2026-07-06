import { webcrypto } from 'node:crypto';

import * as x509 from '@peculiar/x509';
import { X509Certificate } from '@peculiar/x509';
import { exportJWK, importX509, type JWK } from 'jose';

/** Extracts relevant data from an X.509 certificate provided
 * as an ArrayBuffer and returns it in a structured format.
 *
 * @param input - An object containing the certificate as an ArrayBuffer.
 * @returns An object containing the issuer name, validity period, PEM-encode
 * certificate, serial number, subject name, and thumbprint of the certificate.
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

/** Extracts the public key from the leaf certificate in
 * a certificate chain and returns it as a JWK.
 *
 * @param input - An object containing the certificate chain
 * (in x5c format) and the expected algorithm of the public key.
 * @returns A JWK representing the public key extracted from the
 * leaf certificate, with `kid`, `use`, and `alg` parameters set.
 */
export const getCertificateChainPublicKey = async (input: { alg: string; certificateChain: readonly unknown[] }) => {
  const [leafCertificate] = input.certificateChain;
  if (leafCertificate === undefined) {
    throw new Error('x5c certificate not found');
  }
  if (typeof leafCertificate !== 'string') {
    throw new TypeError('Invalid x5c certificate format');
  }

  const key = await importX509(convertBase64DerToPem(leafCertificate), input.alg, {
    extractable: true
  });

  return await exportJWK(key);
};

/** Validates a certificate chain against a set of trusted root certificates
 * and returns an error if the chain is invalid.
 *
 * @param input - An object containing the certificate chain to validate,
 * the trusted root certificates, and an optional validation date.
 * @returns void if the certificate chain is valid.
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
    const cert = parsedChain[i];
    const issuerCertificate = parsedChain[i - 1];
    await cert.verify({ date: validationDate, publicKey: issuerCertificate.publicKey });
  }
};

/** Creates a self-signed X.509 certificate from a JWK containing a
 * public/private key pair.
 *
 * @param jwk - A JWK containing the public and private key material
 * to be included in the certificate.
 * @returns A PEM-encoded string representation of the generated
 * X.509 certificate.
 */
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

/** Converts a base64 DER-encoded certificate string to PEM format
 * by adding the appropriate header and footer lines.
 *
 * @param certificate - The base64 DER-encoded certificate string
 * @returns The certificate in PEM format
 */
export const convertBase64DerToPem = (certificate: string): string =>
  `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;

/** Converts a PEM-encoded certificate to base64 DER format
 * by parsing it and re-encoding the raw data.
 *
 * @param certificatePem - The PEM-encoded certificate string
 * @returns The certificate in base64 DER format
 */
export const convertPemToBase64Der = (certificatePem: string): string =>
  Buffer.from(new X509Certificate(certificatePem).rawData).toString('base64');

/** Removes private key material and key_ops from a JWK to produce a public JWK.
 *
 * @param jwk - The input JWK, which may contain private key parameters and/or key_ops.
 * @returns A new JWK object containing only the public key parameters and no key_ops.
 */
function stripPrivateKeyMaterial(jwk: JWK): JWK {
  const { d: _d, key_ops: _key_ops, ...publicJwk } = jwk as JWK & { d?: string; key_ops?: string[] };
  return publicJwk;
}
