import { describe, expect, it } from 'vitest';

import { ECKey, ECPrivateKey, ECPrivateKeyWithKidCodec, JwkPrivateKey, JwkPublicKey } from '../z-jwk.js';

const validECPublicKey = {
  crv: 'P-256',
  kid: 'test-key-1',
  kty: 'EC' as const,
  use: 'sig' as const,
  x: 'someX',
  y: 'someY'
};

const validECPrivateKey = {
  ...validECPublicKey,
  d: 'someD'
};

describe('ECKey', () => {
  it('parses a valid EC public key', () => {
    const result = ECKey.safeParse(validECPublicKey);
    expect(result.success).toBe(true);
  });

  it('rejects a key missing x or y', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { x: _x, ...missing } = validECPublicKey;
    const result = ECKey.safeParse(missing);
    expect(result.success).toBe(false);
  });
});

describe('ECPrivateKey', () => {
  it('parses a valid EC private key', () => {
    const result = ECPrivateKey.safeParse(validECPrivateKey);
    expect(result.success).toBe(true);
  });

  it('rejects when d is missing', () => {
    const result = ECPrivateKey.safeParse(validECPublicKey);
    expect(result.success).toBe(false);
  });
});

describe('JwkPublicKey', () => {
  it('parses EC public key via discriminated union', () => {
    const result = JwkPublicKey.safeParse(validECPublicKey);
    expect(result.success).toBe(true);
  });
});

describe('JwkPrivateKey', () => {
  it('parses EC private key via discriminated union', () => {
    const result = JwkPrivateKey.safeParse(validECPrivateKey);
    expect(result.success).toBe(true);
  });
});

describe('ECPrivateKeyWithKidCodec', () => {
  it('requires kid field', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { kid: _kid, ...noKid } = validECPrivateKey;
    const result = ECPrivateKeyWithKidCodec.safeParse(noKid);
    expect(result.success).toBe(false);
  });

  it('parses when kid is present', () => {
    const result = ECPrivateKeyWithKidCodec.safeParse(validECPrivateKey);
    expect(result.success).toBe(true);
  });
});
