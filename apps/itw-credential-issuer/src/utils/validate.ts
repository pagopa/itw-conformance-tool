import { X509Certificate } from '@peculiar/x509';
import { importJWK, type JWK } from 'jose';
import { z } from 'zod';

const jwkSchema = z.looseObject({
  kty: z.string(),
  kid: z.string().min(1),
  use: z.enum(['sig', 'enc']).optional(),
  alg: z.string().optional(),
  key_ops: z.array(z.string()).optional(),

  // RSA fields
  n: z.string().optional(),
  e: z.string().optional(),

  // EC / OKP private key scalar
  d: z.string().optional(),

  // EC / OKP public key coordinates
  x: z.string().optional(),
  y: z.string().optional(),
  crv: z.string().optional()
});

const jwksSchema = z.object({
  keys: z.array(jwkSchema).min(1)
});

/** Validates a JWK Set (JWKS) for structural correctness and
 * cryptographic integrity
 *
 * @param jwks - The value to validate (typically the result of `JSON.parse` on the stored JWKS file)
 * @returns A promise that resolves if the JWKS is valid, or rejects with an error describing the validation failure
 */
export async function validateJWKS(jwks: unknown): Promise<void> {
  const parsed = jwksSchema.parse(jwks);

  const seenKids = new Set<string>();
  for (const key of parsed.keys) {
    if (seenKids.has(key.kid)) {
      throw new Error(`Duplicate kid found in JWKS: ${key.kid}`);
    }
    seenKids.add(key.kid);
    if (key.use === 'enc' && key.alg === undefined) {
      throw new Error(`Key with kid '${key.kid}' has use=enc but no alg specified`);
    }
    await importJWK(key as JWK, key.alg);
  }
}

/** Decodes a PEM string to an ArrayBuffer by stripping headers and base64-decoding the body. */
function decodePem(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----[^-]+-----|\s/g, '');
  const buf = Buffer.from(b64, 'base64');
  // slice ensures we get a standalone ArrayBuffer, not a view into a shared buffer
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/** Validates that an IACA X.509 certificate and its
 * PKCS#8 private key form a valid cryptographic pair
 *
 * @param certPem - PEM-encoded X.509 IACA certificate
 * @param keyPem - PEM-encoded PKCS#8 IACA private key (EC P-256)
 */
export async function validateIACAKeyPair(certPem: string, keyPem: string): Promise<void> {
  const cert = new X509Certificate(certPem);

  const ecAlg = { name: 'ECDSA', namedCurve: 'P-256' } as const;
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey('pkcs8', decodePem(keyPem), ecAlg, false, ['sign']),
    crypto.subtle.importKey('spki', cert.publicKey.rawData, ecAlg, false, ['verify'])
  ]);

  const challenge = crypto.getRandomValues(new Uint8Array(16));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, challenge);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, challenge);

  if (!valid) {
    throw new Error('IACA certificate and private key do not correspond');
  }
}
