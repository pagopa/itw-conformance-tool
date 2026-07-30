import { type JsonWebKey, createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';

import { getCertificateData, validateCertificateChain } from '@itw-conformance-tool/crypto';
import { CoseKey } from '@owf/mdoc';
import { X509Certificate } from '@peculiar/x509';
import { exportJWK, importX509 } from 'jose';

import type { DigestAlgorithm, MdocContext, Sign1 } from '@owf/mdoc';

const digestAlgorithmToNode = (digestAlgorithm: DigestAlgorithm): string =>
  digestAlgorithm.replace('-', '').toLowerCase();

const keyToNodeDigestAlgorithm = (key: CoseKey): string => {
  switch (key.jwk.alg) {
    case 'ES256':
      return 'sha256';
    case 'ES384':
      return 'sha384';
    case 'ES512':
      return 'sha512';
    default:
      break;
  }

  switch (key.jwk.crv) {
    case 'P-256':
      return 'sha256';
    case 'P-384':
      return 'sha384';
    case 'P-521':
      return 'sha512';
    default:
      throw new Error('Unsupported mdoc key algorithm for ECDSA signing');
  }
};

const toNodeJwk = (key: CoseKey): JsonWebKey => {
  const { alg, crv, d, k, keyOps, kid, kty, x, y } = key.jwk;

  return Object.fromEntries(
    Object.entries({
      alg,
      crv,
      d,
      k,
      key_ops: keyOps,
      kid,
      kty,
      x,
      y
    }).filter(([, value]) => value !== undefined)
  ) as JsonWebKey;
};

const toPublicNodeJwk = (key: CoseKey): JsonWebKey => {
  const { d, ...publicJwk } = toNodeJwk(key);
  void d;

  return publicJwk;
};

const getIssuerNameFieldMatches = (issuerName: string, field: string): string[] => {
  const pattern = new RegExp(`(?:^|,\\s*)${field}=([^,]+)`, 'g');
  const matches = Array.from(issuerName.matchAll(pattern));

  return matches.map((match) => match[1].trim());
};

const getCertificateArrayBuffer = (certificate: Uint8Array): ArrayBuffer => Uint8Array.from(certificate).buffer;

const unsupportedMacKeyCalculation = (): never => {
  throw new Error('MAC-based mdoc flows are not supported');
};

const verifySign1 = async (input: { key: CoseKey; sign1: Sign1 }): Promise<boolean> => {
  const publicKey = createPublicKey({
    format: 'jwk',
    key: toPublicNodeJwk(input.key)
  });

  return verify(
    keyToNodeDigestAlgorithm(input.key),
    input.sign1.toBeSigned,
    {
      dsaEncoding: 'ieee-p1363',
      key: publicKey
    },
    input.sign1.signature
  );
};

export const mdocContext: MdocContext = {
  cose: {
    mac0: {
      sign: unsupportedMacKeyCalculation,
      verify: unsupportedMacKeyCalculation
    },
    sign1: {
      sign: async ({ key, toBeSigned }) => {
        const privateKey = createPrivateKey({
          format: 'jwk',
          key: toNodeJwk(key)
        });

        return sign(keyToNodeDigestAlgorithm(key), toBeSigned, {
          dsaEncoding: 'ieee-p1363',
          key: privateKey
        });
      },
      verify: verifySign1
    }
  },
  crypto: {
    calculateEphemeralMacKey: unsupportedMacKeyCalculation,
    digest: async ({ bytes, digestAlgorithm }) =>
      createHash(digestAlgorithmToNode(digestAlgorithm)).update(bytes).digest(),
    random: (length) => {
      const bytes = randomBytes(length);
      if (length === 4) {
        bytes[0] &= 0x7f;
      }
      return bytes;
    }
  },
  x509: {
    getCertificateData: async ({ certificate }) =>
      await getCertificateData({
        certificate: getCertificateArrayBuffer(certificate)
      }),
    getIssuerNameField: ({ certificate, field }) => {
      const parsedCertificate = new X509Certificate(getCertificateArrayBuffer(certificate));

      return getIssuerNameFieldMatches(parsedCertificate.issuerName.toString(), field);
    },
    getPublicKey: async ({ alg, certificate }) => {
      const publicKey = await importX509(
        new X509Certificate(getCertificateArrayBuffer(certificate)).toString('pem'),
        alg,
        { extractable: true }
      );

      return CoseKey.fromJwk((await exportJWK(publicKey)) as Record<string, unknown>);
    },
    verifyCertificateChain: async ({ now, trustedCertificates, x5chain }) => {
      if (trustedCertificates.length === 0) {
        throw new Error('trustedCertificates must not be empty');
      }

      if (x5chain.length === 0) {
        throw new Error('x5chain must not be empty');
      }

      await validateCertificateChain({
        now,
        trustedCertificates: trustedCertificates.map((c) => getCertificateArrayBuffer(c)) as [
          ArrayBuffer,
          ...ArrayBuffer[]
        ],
        x5chain: x5chain.map((c) => getCertificateArrayBuffer(c)) as [ArrayBuffer, ...ArrayBuffer[]]
      });
    }
  }
};
