import * as x509 from "@peculiar/x509";
import { X509Certificate } from "@peculiar/x509";
import { exportJWK, importX509 } from "jose";

/**
 * Extracts certificate details and metadata from a raw X.509 certificate.
 */
export const getCertificateData = async (input: {
  certificate: ArrayBuffer;
}) => {
  const certificate = new X509Certificate(input.certificate);
  const thumbprint = await certificate.getThumbprint(crypto);
  const thumbprintHex = Buffer.from(thumbprint).toString("hex");
  return {
    issuerName: certificate.issuerName.toString(),
    notAfter: certificate.notAfter,
    notBefore: certificate.notBefore,
    pem: certificate.toString(),
    serialNumber: certificate.serialNumber,
    subjectName: certificate.subjectName.toString(),
    thumbprint: thumbprintHex,
  };
};

/**
 * Extracts the leaf public key in JWK format from an X.509 certificate chain.
 */
export const getCertificateChainPublicKey = async (input: {
  alg: string;
  certificateChain: readonly unknown[];
}) => {
  const [leafCertificate] = input.certificateChain;
  if (leafCertificate === undefined) {
    throw new Error("x5c certificate not found");
  }

  if (typeof leafCertificate !== "string") {
    throw new Error("Invalid x5c certificate format");
  }

  const key = await importX509(
    convertBase64DerToPem(leafCertificate),
    input.alg,
    {
      extractable: true,
    },
  );

  return await exportJWK(key);
};

/**
 * Validates a chain of X.509 certificates against a trusted list.
 */
export const validateCertificateChain = async (input: {
  now?: Date;
  trustedCertificates: [ArrayBuffer, ...ArrayBuffer[]];
  x5chain: [ArrayBuffer, ...ArrayBuffer[]];
}) => {
  const { now, trustedCertificates, x5chain: certificateChain } = input;
  if (certificateChain.length === 0) {
    throw new Error("Certificate chain is empty");
  }

  const validationDate = now ?? new Date();

  const parsedLeafCertificate = new x509.X509Certificate(certificateChain[0]);

  const parsedCertificates = certificateChain.map(
    (c) => new x509.X509Certificate(c),
  );

  const certificateChainBuilder = new x509.X509ChainBuilder({
    certificates: parsedCertificates,
  });

  const chain = await certificateChainBuilder.build(parsedLeafCertificate);

  // The chain is reversed here as the `x5c` header (the expected input),
  // has the leaf certificate as the first entry, while the `x509` library expects this as the last
  let parsedChain = chain
    .map((c) => new x509.X509Certificate(c.rawData))
    .reverse();

  if (parsedChain.length !== certificateChain.length) {
    throw new Error(
      "Could not parse the full chain. Likely due to incorrect ordering",
    );
  }

  const parsedTrustedCertificates = trustedCertificates.map(
    (trustedCertificate) => new x509.X509Certificate(trustedCertificate),
  );

  const trustedCertificateIndex = parsedChain.findIndex((cert) =>
    parsedTrustedCertificates.some((tCert) => cert.equal(tCert)),
  );

  if (trustedCertificateIndex === -1) {
    throw new Error(
      "No trusted certificate was found while validating the X.509 chain",
    );
  }

  // Pop everything off above the index of the trusted as it is not relevant for validation
  parsedChain = parsedChain.slice(0, trustedCertificateIndex);

  // Verify the certificate with the publicKey of the certificate above
  for (let i = 0; i < parsedChain.length; i++) {
    const cert = parsedChain[i];
    const previousCertificate = parsedChain[i - 1];
    const publicKey = previousCertificate
      ? previousCertificate.publicKey
      : undefined;
    await cert?.verify({ date: validationDate, publicKey });
  }
};

/**
 * Converts a base64-encoded DER certificate to PEM format.
 *
 * @param certificate - The base64-encoded DER certificate.
 * @returns The PEM-formatted certificate.
 */
export const convertBase64DerToPem = (certificate: string): string =>
  `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
