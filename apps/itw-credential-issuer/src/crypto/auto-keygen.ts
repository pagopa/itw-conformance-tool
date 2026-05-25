import { randomUUID } from 'node:crypto';

import {
  BasicConstraintsExtension,
  KeyUsagesExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator
} from '@peculiar/x509';
import { exportJWK, generateKeyPair } from 'jose';

/** Generates a JWK Set containing a single signing key
 * for the issuer, returning it as a JSON string
 *
 * @returns A JSON string representing the JWK Set with the signing key
 */
export async function generateJwks(): Promise<string> {
  const [signPair, encPair] = await Promise.all([
    generateKeyPair('ES256', { extractable: true }),
    generateKeyPair('ES256', { extractable: true })
  ]);

  const [signPrivJwk, encPrivJwk] = await Promise.all([exportJWK(signPair.privateKey), exportJWK(encPair.privateKey)]);

  const jwks = {
    keys: [
      { ...signPrivJwk, kid: randomUUID(), use: 'sig', alg: 'ES256', key_ops: ['sign'] },
      { ...encPrivJwk, kid: randomUUID(), use: 'enc', alg: 'ES256', key_ops: ['encrypt'] }
    ]
  };

  return JSON.stringify(jwks, null, 2);
}

/** Generates a self-signed certificate and corresponding
 * private key for IACA use, returning them as PEM-formatted strings
 *
 * @returns An object containing the certificate and private key in PEM format
 */
export async function generateIaca(): Promise<{ certPem: string; keyPem: string }> {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 10);

  const cert = await X509CertificateGenerator.createSelfSigned({
    keys: keyPair,
    name: 'C=IT, O=ITW Conformance Tool, CN=IACA Self-Signed',
    notBefore: now,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(
        // keyCertSign | cRLSign | digitalSignature
        0x0004 | 0x0002 | 0x0080,
        true
      ),
      await SubjectKeyIdentifierExtension.create(keyPair.publicKey)
    ]
  });

  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const b64 = Buffer.from(pkcs8).toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  const keyPem = `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;

  return { certPem: cert.toString(), keyPem };
}
