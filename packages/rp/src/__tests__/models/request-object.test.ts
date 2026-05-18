import { describe, it, expect } from 'vitest';

import { validateRequestObject, isRequestObjectExpired } from '../../models/request-object.js';

describe('RequestObject Model', () => {
  describe('validateRequestObject', () => {
    it('should validate a correct request object', () => {
      const obj = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300
      };

      const result = validateRequestObject(obj);

      expect(result.iss).toBe('https://rp.example.com');
      expect(result.client_id).toBe('rp.example.com');
      expect(result.nonce).toBe('n-123');
    });

    it('should reject invalid request objects', () => {
      const invalid = {
        iss: 'not-a-url',
        aud: 'wallet'
      };

      expect(() => validateRequestObject(invalid)).toThrow();
    });

    it('should allow optional presentation_definition', () => {
      const obj = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        presentation_definition: { id: 'test', input_descriptors: [] }
      };

      const result = validateRequestObject(obj);
      expect(result.presentation_definition).toBeDefined();
    });
  });

  describe('isRequestObjectExpired', () => {
    it('should detect expired request objects', () => {
      const obj = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: Math.floor(Date.now() / 1000) - 600,
        exp: Math.floor(Date.now() / 1000) - 1
      };

      expect(isRequestObjectExpired(obj)).toBe(true);
    });

    it('should detect non-expired request objects', () => {
      const obj = {
        iss: 'https://rp.example.com',
        aud: 'wallet',
        client_id: 'rp.example.com',
        nonce: 'n-123',
        state: 's-456',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300
      };

      expect(isRequestObjectExpired(obj)).toBe(false);
    });
  });
});
