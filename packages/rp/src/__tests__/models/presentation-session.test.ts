import { describe, it, expect } from 'vitest';

import {
  createPresentationSession,
  isExpiredNow,
  isTerminalState,
  recordToPresentationSession,
  serializeDetails,
  parseDetails,
  type PresentationSessionDetails
} from '../../models/presentation-session.js';

describe('PresentationSession Model', () => {
  describe('createPresentationSession', () => {
    it('should create a new pending session', () => {
      const session = createPresentationSession('test-session-1');

      expect(session.sessionId).toBe('test-session-1');
      expect(session.state).toBe('pending');
      expect(session.flowType).toBe('presentation');
      expect(session.values).toEqual([]);
      expect(session.createdAt).toBeDefined();
      expect(session.expiresAt).toBeDefined();
    });

    it('should respect custom TTL', () => {
      const beforeCreate = Date.now();
      const session = createPresentationSession('test-session-2', 60);
      const afterCreate = Date.now();

      const expectedMinExpiry = beforeCreate + 60 * 1000;
      const expectedMaxExpiry = afterCreate + 60 * 1000;

      expect(session.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMinExpiry);
      expect(session.expiresAt.getTime()).toBeLessThanOrEqual(expectedMaxExpiry);
    });
  });

  describe('isTerminalState', () => {
    it('should identify terminal states', () => {
      expect(isTerminalState('verified')).toBe(true);
      expect(isTerminalState('rejected')).toBe(true);
      expect(isTerminalState('expired')).toBe(true);
      expect(isTerminalState('denied')).toBe(true);
    });

    it('should identify non-terminal states', () => {
      expect(isTerminalState('pending')).toBe(false);
    });
  });

  describe('isExpiredNow', () => {
    it('should detect expired sessions', () => {
      const pastDate = new Date(Date.now() - 1000);
      expect(isExpiredNow(pastDate)).toBe(true);
    });

    it('should detect non-expired sessions', () => {
      const futureDate = new Date(Date.now() + 10000);
      expect(isExpiredNow(futureDate)).toBe(false);
    });
  });

  describe('serializeDetails and parseDetails', () => {
    it('should serialize and deserialize details', () => {
      const original: PresentationSessionDetails = {
        redirectUri: 'http://example.com/callback',
        values: [{ name: 'John', age: '30' }]
      };

      const serialized = serializeDetails(original);
      const parsed = parseDetails(serialized);

      expect(parsed).toEqual(original);
    });

    it('should handle parse errors gracefully', () => {
      const result = parseDetails('invalid json');
      expect(result).toEqual({ redirectUri: '', values: [] });
    });
  });

  describe('recordToPresentationSession', () => {
    it('should convert database record to domain model', () => {
      const now = new Date();
      const record = {
        id: 'session-123',
        state: 'verified',
        details: JSON.stringify({ redirectUri: 'http://example.com', values: [] }),
        created_at: now.toISOString(),
        expires_at: new Date(now.getTime() + 300000).toISOString(),
        verified_at: now.toISOString()
      };

      const session = recordToPresentationSession(record);

      expect(session.sessionId).toBe('session-123');
      expect(session.state).toBe('verified');
      expect(session.redirectUri).toBe('http://example.com');
      expect(session.verifiedAt).toBeDefined();
    });
  });
});
