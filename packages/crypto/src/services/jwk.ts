import { randomUUID } from 'node:crypto';

import { exportJWK, generateKeyPair as joseGenerateKeyPair } from 'jose';

import { generateKeyPair } from './keys.js';

import type { GenerateJwksOptions, JwkDescriptor, JwkRecord, JwkSet, KeyDescriptor } from '../types/types.js';

const allOps = new Set(['sign', 'verify', 'encrypt', 'decrypt', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey']);

const encryptionOps = new Set(['encrypt', 'decrypt', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey']);

const signingOps = new Set(['sign', 'verify']);

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

  return alg.startsWith('ECDH-ES') ? ['deriveKey'] : ['decrypt'];
}

/** Validates the provided 'key_ops' against the intended use and algorithm,
 * ensuring that they are consistent and do not contain incompatible operations.
 *
 * @param use - The intended use of the key ('sig' for signing, 'enc' for encryption).
 * @param alg - The algorithm for which the key is intended.
 * @param keyOps - An optional array of key operations to validate. If not provided, no
 * validation is performed.
 * @returns void
 */
function validateKeyOps(use: 'sig' | 'enc', alg: string, keyOps?: string[]): void {
  if (!keyOps || keyOps.length === 0) {
    return;
  }

  for (const op of keyOps) {
    if (!allOps.has(op)) {
      throw new Error(`Unknown key operation: ${op}`);
    }
  }

  if (use === 'sig' && keyOps.some((op) => encryptionOps.has(op))) {
    throw new Error(`Invalid key_ops for use=sig and alg=${alg}: ${keyOps.join(', ')}`);
  }

  if (use === 'enc' && keyOps.some((op) => signingOps.has(op))) {
    throw new Error(`Invalid key_ops for use=enc and alg=${alg}: ${keyOps.join(', ')}`);
  }

  if (alg.startsWith('ECDH-ES')) {
    const allowed = new Set(['deriveKey', 'deriveBits']);
    if (keyOps.some((op) => !allowed.has(op))) {
      throw new Error(`Invalid key_ops for alg=${alg}: ${keyOps.join(', ')}`);
    }
  }
}

/** Ensures that all keys in the generated JWKS have unique 'kid' values, throwing
 * an error if duplicates are found.
 *
 * @param keys - An array of JWK records to check for unique 'kid' values.
 * @returns void
 */
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

      if (spec.kid && count !== 1) {
        throw new Error(`kid cannot be used with count > 1 for alg ${spec.alg}`);
      }

      return Array.from({ length: count }, async (_unused, index) => {
        const kid = spec.kid ?? (spec.kidPrefix ? `${spec.kidPrefix}-${index + 1}` : randomUUID());

        const { privateKey } = await joseGenerateKeyPair(spec.alg, {
          extractable: spec.extractable ?? true
        });
        const privateJwk = await exportJWK(privateKey);

        return {
          ...privateJwk,
          kid,
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

/** Backward-compatible helper that returns a JWKS containing one RSA
 * signing key descriptor.
 *
 * @param descriptor - Key identifier and intended use.
 * @returns The generated JWKS as pretty-printed JSON.
 * @returns The generated JWKS.
export function generateSigningJwks(descriptor: KeyDescriptor): JwkSet {
  const { privateKey } = generateKeyPair({ use: 'sig', keyType: 'rsa' });

  const privateJwk = privateKey.export({ format: 'jwk' });

  return {
    keys: [
      {
        ...(privateJwk as JwkRecord),
        kid: descriptor.kid,
        alg: 'RS256',
        use: descriptor.use,
        key_ops: descriptor.use === 'sig' ? ['sign'] : ['decrypt']
      }
    ]
  };
}

/** Backward-compatible helper that returns a JWKS for configurable
 * key generation options.
 *
 * @param options - Key generation options with one or more key specs.
 * @returns The generated JWKS as JSON string.
 * @returns The generated JWKS.
export async function generateConfigurableJwks(options: GenerateJwksOptions): Promise<JwkSet> {
  return generateJWKS(options);
}

/** Generates an EC private key in JWK format
 * using the curve implied by the selected algorithm.
 *
 * @param descriptor - Key metadata including kid, alg, use, and key_ops.
 * @returns A JwkSet representing the private JWK.
 */
export function generateEcPrivateJwk(descriptor: JwkDescriptor): JwkSet {
  validateKeyOps(descriptor.use, descriptor.alg, descriptor.keyOps);

  const { privateKey } = generateKeyPair({
    use: descriptor.use,
    keyType: 'ec',
    alg: descriptor.alg
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
