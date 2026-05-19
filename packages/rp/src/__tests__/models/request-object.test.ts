import { describe, expect, it } from 'vitest';

import { createRequestObject } from '../../models/request-object.js';

describe('createRequestObject', () => {
  it('returns an object with empty header and claims when only the JWT is provided', () => {
    const jwt = 'header.payload.signature';
    const obj = createRequestObject(jwt);

    expect(obj.jwt).toBe(jwt);
    expect(obj.header).toEqual({});
    expect(obj.claims).toEqual({});
  });

  it('preserves the provided claims and header', () => {
    const jwt = 'h.p.s';
    const claims = { client_id: 'rp.example', nonce: 'n-123' };
    const header = { alg: 'ES256', typ: 'oauth-authz-req+jwt' };

    const obj = createRequestObject(jwt, claims, header);

    expect(obj.claims).toEqual(claims);
    expect(obj.header).toEqual(header);
  });
});
