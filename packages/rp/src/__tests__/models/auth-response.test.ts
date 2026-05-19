import { describe, it, expect } from 'vitest';

import { createSuccessAuthResponse, createErrorAuthResponse } from '../../models/auth-response.js';

describe('AuthResponse', () => {
  describe('createSuccessAuthResponse', () => {
    it('should create a success response with code', () => {
      const response = createSuccessAuthResponse('auth-code-123');

      expect(response.code).toBe('auth-code-123');
      expect(response.error).toBeUndefined();
      expect(response.state).toBeUndefined();
    });

    it('should create a success response with code and state', () => {
      const response = createSuccessAuthResponse('auth-code-123', 'state-xyz');

      expect(response.code).toBe('auth-code-123');
      expect(response.state).toBe('state-xyz');
      expect(response.error).toBeUndefined();
    });
  });

  describe('createErrorAuthResponse', () => {
    it('should create an error response', () => {
      const response = createErrorAuthResponse('invalid_request', 'Missing client_id');

      expect(response.error).toBe('invalid_request');
      expect(response.errorDescription).toBe('Missing client_id');
      expect(response.code).toBeUndefined();
    });

    it('should create an error response with state', () => {
      const response = createErrorAuthResponse('access_denied', 'User denied access', 'state-abc');

      expect(response.error).toBe('access_denied');
      expect(response.state).toBe('state-abc');
    });
  });
});
