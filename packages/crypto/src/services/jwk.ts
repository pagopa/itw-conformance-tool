import { generateKeyPairSync, randomUUID } from 'node:crypto';

import { exportJWK, generateKeyPair } from 'jose';

import type { GenerateJwksOptions, JwkDescriptor, JwkRecord, JwkSet, KeyDescriptor } from '../types/types.js';

const curveMap = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521'
} as const;

const signingOps = new Set([
  'sign',
  'verify'
]);

const encryptionOps = new Set([
  'encrypt',
  'decrypt',
  'deriveKey',
  'deriveBits',
  'wrapKey',
  'unwrapKey'
]);

const allOps = new Set([
  'sign',
  'verify',
  'encrypt',
  'decrypt',
  'deriveKey',
  'deriveBits',
  'wrapKey',
  'unwrapKey'
]);

/** Generates an RSA key pair and returns the private key 
 * in both PEM and JWK formats.
 *
 * @returns An object containing the private key in PEM 
 * format and as a JWK record.
 */
function generateRsaKeyPair(): { privateKeyPem: string; privateJwk: JwkRecord } {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001
  });

  const privateJwk = privateKey.export({ format: 'jwk' });
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

  return { privateKeyPem, privateJwk };
}

/** Resolves the default 'key_ops' for a generated key based on its
 * intended use and algorithm.
 *
 * @param use - The intended use of the key ('sig' for signing, 'enc' for encryption).
 * @param alg - The algorithm for which the key is intended.
 * @returns An array of default key operations for the given use and algorithm.
 */
function resolveDefaultKeyOps(use: 'sig' | 'enc', alg: string): string[] {
  if (use === 'sig') {
    return ['sign'];
  }

  return alg === 'ECDH-ES' ? ['deriveKey'] : ['decrypt'];
}

function validateKeyOps(use: 'sig' | 'enc', alg: string, keyOps?: string[]): void {
  if (!keyOps || keyOps.length === 0) {
    return;
  }

  for (const op of keyOps) {
    if (!allOps.has(op)) {
      throw new Error(
        `Unknown key operation: ${op}`
      );
    }
  }

  if (use === 'sig' && keyOps.some((op) => encryptionOps.has(op))) {
    throw new Error(`Invalid key_ops for use=sig and alg=${alg}: ${keyOps.join(', ')}`);
  }

  if (use === 'enc' && keyOps.some((op) => signingOps.has(op))) {
    throw new Error(`Invalid key_ops for use=enc and alg=${alg}: ${keyOps.join(', ')}`);
  }

  if (alg === 'ECDH-ES') {
    const allowed = new Set(['deriveKey', 'deriveBits']);
    if (keyOps.some((op) => !allowed.has(op))) {
      throw new Error(`Invalid key_ops for alg=ECDH-ES: ${keyOps.join(', ')}`);
    }
  }
}

function ensureUniqueKids(keys: JwkRecord[]): void {
  const seen = new Set<string>();
  const duplicates = new Set<string>();

  for (const key of keys) {
    const kid = key.kid;
    if (typeof kid !== 'string') {
      continue;
    }

    if (seen.has(kid)) {
      duplicates.add(kid);
    }

    seen.add(kid);
  }

  if (duplicates.size > 0) {
    throw new Error(`Duplicate kid values in JWKS: ${Array.from(duplicates).join(', ')}`);
  }
}

/** Resolves the 'kid' for a generated key based on the provided spec,
 * count, and index.
 *
 * @param spec - The key specification containing optional 'kid' and 'kidPrefix'.
 * @param count - The total number of keys to be generated for the given spec.
 * @param index - The index of the current key being generated.
 * @returns The resolved 'kid' for the generated key.
 */
function resolveKid(spec: GenerateJwksOptions['keys'][number], count: number, index: number): string {
  if (spec.kid) {
    if (count > 1) {
      throw new Error('Cannot use a fixed kid when count > 1; use kidPrefix or count=1');
    }

    return spec.kid;
  }

  const prefix = spec.kidPrefix ?? `${spec.use}-${spec.alg}`;
  const suffix = count === 1 ? randomUUID() : `${index + 1}-${randomUUID()}`;

  return `${prefix}-${suffix}`;
}

/** Generates a configurable JWKS by producing one or more private
 * keys for each requested spec.
 *
 * @param options - Key generation options with one or more key specs.
 * @returns A JwkSet representing the generated JWKS.
 */
export async function generateJWKS(options: GenerateJwksOptions): Promise<JwkSet> {
  const specs = options.keys;

  if (!Array.isArray(specs) || specs.length === 0) {
    throw new Error('generateJWKS requires at least one key specification');
  }

  const generated = await Promise.all(
    specs.flatMap((spec) => {
      const count = spec.count ?? 1;
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`Invalid key count for alg ${spec.alg}: count must be an integer >= 1`);
      }

      validateKeyOps(spec.use, spec.alg, spec.keyOps);

      return Array.from({ length: count }, async (_, index) => {
        const { privateKey } = await generateKeyPair(spec.alg, {
          extractable: spec.extractable ?? true
        });
        const privateJwk = await exportJWK(privateKey);

        return {
          ...privateJwk,
          kid: resolveKid(spec, count, index),
          use: spec.use,
          alg: spec.alg,
          key_ops: spec.keyOps ?? resolveDefaultKeyOps(spec.use, spec.alg)
        };
      });
    })
  );

  ensureUniqueKids(generated);

  return { keys: generated };
}

/** Generates a JWK Set containing a single RSA signing key.
 *
 * @param descriptor - Key identifier and intended use.
 * @returns A JwkSet representing the JWK Set.
 */
export function generateSigningJwks(descriptor: KeyDescriptor): JwkSet {
  if (descriptor.use !== 'sig') {
    throw new Error(
      'generateSigningJwks only supports use="sig"'
    );
  }

  const { privateJwk } = generateRsaKeyPair();

  return {
    keys: [
      {
        ...privateJwk,
        kid: descriptor.kid,
        alg: 'RS256',
        use: 'sig',
        key_ops: ['sign']
      }
    ]
  };
}

/** Generates an EC private key in JWK format
 * using the curve implied by the selected algorithm.
 *
 * @param descriptor - Key metadata including kid, alg, use, and key_ops.
 * @returns A JwkSet representing the private JWK.
 */
export function generateEcPrivateJwk(descriptor: JwkDescriptor): JwkSet {
  const curve = curveMap[descriptor.alg as keyof typeof curveMap];

  if (!curve) {
    throw new Error(`Unsupported EC algorithm: ${descriptor.alg}`);
  }

  validateKeyOps(descriptor.use, descriptor.alg, descriptor.keyOps);

  const { privateKey } = generateKeyPairSync('ec', {
    namedCurve: curve
  });

  const privateJwk = privateKey.export({ format: 'jwk' });

  return {
    keys: [
      {
        ...privateJwk,
        kid: descriptor.kid,
        alg: descriptor.alg,
        use: descriptor.use,
        key_ops: descriptor.keyOps
      }
    ]
  };
}
