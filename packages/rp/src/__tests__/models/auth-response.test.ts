import { describe, it, expect } from 'vitest';

import { isAuthResponseError, isAuthResponseSuccess, type AuthResponse } from '../../models/auth-response.js';

describe('AuthResponse Model', () => {
  describe('isAuthResponseError', () => {
    it('should identify error responses', () => {
      const errorResponse: AuthResponse = {
        error: 'invalid_request',
        error_description: 'Request is invalid',
        state: 's-123'
      };

      expect(isAuthResponseError(errorResponse)).toBe(true);
    });

    it('should reject success responses', () => {
      const successResponse: AuthResponse = {
        redirect_uri: 'http://example.com/callback'
      };

      expect(isAuthResponseError(successResponse)).toBe(false);
    });
  });

  describe('isAuthResponseSuccess', () => {
    it('should identify success responses', () => {
      const successResponse: AuthResponse = {
        redirect_uri: 'http://example.com/callback'
      };

      expect(isAuthResponseSuccess(successResponse)).toBe(true);
    });

    it('should reject error responses', () => {
      const errorResponse: AuthResponse = {
        error: 'access_denied',
        error_description: 'User denied',
        state: 's-123'
      };

      expect(isAuthResponseSuccess(errorResponse)).toBe(false);
    });
  });
});
