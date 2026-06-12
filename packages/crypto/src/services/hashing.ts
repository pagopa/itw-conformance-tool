import { createHash, randomBytes } from 'node:crypto';

import type { GenerateRandomCallback, HashAlgorithm } from '../types/types.js';

/**
 * Map of OAuth2 hash algorithm names to Node.js hash algorithm names.
 */
const HASH_ALG_MAP: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512'
};

/**
 * Generates a hash digest for the given data using the specified algorithm.
 *
 * @param data - The data to hash
 * @param alg - The hash algorithm (e.g., 'sha-256', 'sha-384', 'sha-512')
 * @returns The hash digest as a Uint8Array
 * @throws Error if the hash algorithm is unsupported
 */
export const hashCallback = (data: Uint8Array, alg: HashAlgorithm): Uint8Array => {
  const nodeAlg = HASH_ALG_MAP[alg];
  if (!nodeAlg) throw new Error(`Unsupported hash algorithm: ${alg}`);
  return new Uint8Array(createHash(nodeAlg).update(data).digest());
};

/**
 * Generates random bytes using Node.js crypto module.
 *
 * @param byteLength - The number of random bytes to generate
 * @returns Random bytes as a Uint8Array
 */
export const generateRandomCallback: GenerateRandomCallback = (byteLength): Uint8Array =>
  new Uint8Array(randomBytes(byteLength));

/**
 * Creates a SHA-256 hash of the given data.
 *
 * @param data - The data to hash
 * @returns The SHA-256 hash digest
 */
export const sha256 = (data: Buffer | Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(data).digest());

/**
 * Generates cryptographically secure random bytes.
 *
 * @param length - The number of bytes to generate
 * @returns Random bytes as a Uint8Array
 */
export const generateRandomBytes = (length: number): Uint8Array => new Uint8Array(randomBytes(length));
