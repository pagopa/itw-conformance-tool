import { randomBytes } from 'node:crypto';

/** Generates cryptographically secure random bytes.
 *
 * @param length - The number of bytes to generate
 * @returns Random bytes as a Uint8Array
 */
export const generateRandomBytes = (length: number): Uint8Array => new Uint8Array(randomBytes(length));
