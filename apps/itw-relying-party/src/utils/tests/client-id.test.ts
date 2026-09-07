import { describe, expect, it } from 'vitest';

import { toFederationClientId } from '../request-object.js';

const RP_BASE_URL = 'https://rp.example.org';

describe('toFederationClientId', () => {
  it('carries the entity identifier, which is what points the wallet at the Trust Chain', () => {
    expect(toFederationClientId(RP_BASE_URL)).toBe(`openid_federation:${RP_BASE_URL}`);
  });

  it('rejects an empty entity identifier rather than emitting a bare prefix', () => {
    expect(() => toFederationClientId('')).toThrow(/entity identifier is required/);
  });
});
