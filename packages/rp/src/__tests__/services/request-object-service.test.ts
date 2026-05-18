import { beforeEach, describe, expect, it } from 'vitest';

import { createRequestObject } from '../../models/request-object.js';
import { InvalidRequestObjectJwtError, RequestObjectService } from '../../services/request-object-service.js';

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value), 'utf-8').toString('base64url');
}

function makeJwt(header: object, payload: object, signature = 'sig'): string {
  return `${b64url(header)}.${b64url(payload)}.${signature}`;
}

describe('RequestObjectService', () => {
  let service: RequestObjectService;

  beforeEach(() => {
    service = new RequestObjectService();
  });

  describe('parse', () => {
    it('decodes the header and payload of a well-formed JWT', () => {
      const jwt = makeJwt(
        { alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: 'k-1' },
        { client_id: 'rp.example', nonce: 'n-123', state: 's-456', aud: 'wallet' }
      );

      const result = service.parse(jwt);

      expect(result.jwt).toBe(jwt);
      expect(result.header).toEqual({ alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: 'k-1' });
      expect(result.claims).toMatchObject({
        client_id: 'rp.example',
        nonce: 'n-123',
        state: 's-456',
        aud: 'wallet'
      });
    });

    it('throws when the JWT does not have three segments', () => {
      expect(() => service.parse('header.payload')).toThrow(InvalidRequestObjectJwtError);
      expect(() => service.parse('header.payload.signature.extra')).toThrow(InvalidRequestObjectJwtError);
    });

    it('throws when the header segment is not valid JSON', () => {
      const jwt = `${Buffer.from('not-json', 'utf-8').toString('base64url')}.${b64url({ x: 1 })}.sig`;
      expect(() => service.parse(jwt)).toThrow(/Cannot decode JWT header/);
    });

    it('throws when the payload segment is not valid JSON', () => {
      const jwt = `${b64url({ alg: 'ES256' })}.${Buffer.from('not-json', 'utf-8').toString('base64url')}.sig`;
      expect(() => service.parse(jwt)).toThrow(/Cannot decode JWT payload/);
    });

    it('throws when a segment decodes to a non-object value', () => {
      const jwt = `${b64url({ alg: 'ES256' } as object)}.${Buffer.from(JSON.stringify([1, 2, 3]), 'utf-8').toString('base64url')}.sig`;
      expect(() => service.parse(jwt)).toThrow(/Cannot decode JWT payload/);
    });
  });

  describe('validate', () => {
    it('accepts a request object with alg, client_id, and nonce', () => {
      const requestObject = createRequestObject('h.p.s', { client_id: 'rp.example', nonce: 'n-123' }, { alg: 'ES256' });
      expect(service.validate(requestObject)).toBe(true);
    });

    it('rejects when the JWT has fewer than three segments', () => {
      const requestObject = createRequestObject('h.p', { client_id: 'rp.example', nonce: 'n-123' }, { alg: 'ES256' });
      expect(service.validate(requestObject)).toBe(false);
    });

    it.each([
      ['missing alg', { client_id: 'rp', nonce: 'n' }, {}],
      ['missing client_id', { nonce: 'n' }, { alg: 'ES256' }],
      ['missing nonce', { client_id: 'rp' }, { alg: 'ES256' }],
      ['empty alg', { client_id: 'rp', nonce: 'n' }, { alg: '' }],
      ['empty client_id', { client_id: '', nonce: 'n' }, { alg: 'ES256' }],
      ['empty nonce', { client_id: 'rp', nonce: '' }, { alg: 'ES256' }]
    ] as const)('rejects when %s', (_label, claims, header) => {
      const requestObject = createRequestObject('h.p.s', claims, header);
      expect(service.validate(requestObject)).toBe(false);
    });
  });

  describe('parse + validate (round-trip)', () => {
    it('parses a well-formed JWT into a structure that passes validate()', () => {
      const jwt = makeJwt(
        { alg: 'ES256', typ: 'oauth-authz-req+jwt' },
        { client_id: 'rp.example', nonce: 'n-123', aud: 'wallet' }
      );

      const requestObject = service.parse(jwt);
      expect(service.validate(requestObject)).toBe(true);
    });
  });
});
