import { describe, expect, it } from 'vitest';

import { createSRIHash } from '../sd-jwt.js';

describe('createSRIHash', () => {
  it('returns a sha256- prefixed base64 string', () => {
    const hash = createSRIHash('urn:eu.europa.ec.eudi:pid:1');

    expect(hash).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
  });

  it('produces consistent output for the same input', () => {
    const content = 'urn:eu.europa.ec.eudi:pid:1';

    expect(createSRIHash(content)).toBe(createSRIHash(content));
  });

  it('produces different hashes for different inputs', () => {
    expect(createSRIHash('urn:a')).not.toBe(createSRIHash('urn:b'));
  });
});
