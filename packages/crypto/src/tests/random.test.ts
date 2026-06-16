import { describe, expect, it } from 'vitest';

import { generateRandomBytes } from '../services/random.js';

describe('generateRandomBytes', () => {
  it('returns a Uint8Array with the requested length', () => {
    const bytes = generateRandomBytes(32);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
  });

  it('returns an empty Uint8Array for length 0', () => {
    const bytes = generateRandomBytes(0);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(0);
  });
});
