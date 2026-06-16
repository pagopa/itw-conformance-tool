import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { hashCallback, sha256 } from '../services/hashing.js';

import type { HashAlgorithm } from '../types/types.js';

describe('hashing service', () => {
  it('hashCallback computes sha-256 digest', () => {
    const input = new TextEncoder().encode('abc');

    const digest = hashCallback(input, 'sha256' as HashAlgorithm);

    expect(Buffer.from(digest).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('hashCallback supports sha-384 and matches Node implementation', () => {
    const input = new TextEncoder().encode('itw-conformance-tool');

    const digest = hashCallback(input, 'sha384' as HashAlgorithm);
    const expected = createHash('sha384').update(input).digest();

    expect(Buffer.from(digest).equals(expected)).toBe(true);
  });

  it('throws on unsupported algorithm', () => {
    const input = new Uint8Array([1, 2, 3]);

    expect(() => hashCallback(input, 'sha-1' as never)).toThrow('Unsupported hash algorithm: sha-1');
  });

  it('sha256 computes expected digest for Buffer and Uint8Array', () => {
    const asBuffer = Buffer.from('hello');
    const asUint8 = new TextEncoder().encode('hello');

    const digestFromBuffer = sha256(asBuffer);
    const digestFromUint8 = sha256(asUint8);

    expect(Buffer.from(digestFromBuffer).toString('hex')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
    expect(Buffer.from(digestFromBuffer).equals(Buffer.from(digestFromUint8))).toBe(true);
  });
});
