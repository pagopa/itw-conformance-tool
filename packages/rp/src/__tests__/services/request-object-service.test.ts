import { describe, it, expect } from 'vitest';

import { RequestObjectService, InvalidRequestObjectJwtError } from '../../services/request-object-service.js';

describe('RequestObjectService', () => {
  const service = new RequestObjectService();

  describe('decodeAndValidate', () => {
    it('should decode a valid request object JWT', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: now,
        exp: now + 300
      };

      // Manually create a JWT without signature verification (for testing)
      const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const jwt = `${header}.${body}.`;

      const result = service.decodeAndValidate(jwt);

      expect(result.iss).toBe('https://rp.example.com');
      expect(result.client_id).toBe('rp.example.com');
      expect(result.nonce).toBe('n-123');
    });

    it('should throw on empty JWT', () => {
      expect(() => service.decodeAndValidate('')).toThrow(InvalidRequestObjectJwtError);
    });

    it('should throw on invalid JWT format', () => {
      expect(() => service.decodeAndValidate('invalid.jwt')).toThrow(InvalidRequestObjectJwtError);
    });

    it('should throw on invalid payload structure', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
      const body = Buffer.from(JSON.stringify({ invalid: 'payload' })).toString('base64url');
      const jwt = `${header}.${body}.`;

      expect(() => service.decodeAndValidate(jwt)).toThrow(InvalidRequestObjectJwtError);
    });

    it('should throw on expired request object', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: now - 600,
        exp: now - 300
      };

      const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const jwt = `${header}.${body}.`;

      expect(() => service.decodeAndValidate(jwt)).toThrow(InvalidRequestObjectJwtError);
    });
  });
});
