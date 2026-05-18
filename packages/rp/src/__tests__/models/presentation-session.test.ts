import { describe, it, expect } from 'vitest';

import {
  createPresentationSession,
  isExpiredNow,
  isTerminalState,
  mapToDbState,
  parseDetails,
  recordToPresentationSession,
  serializeDetails
} from '../../models/presentation-session.js';

import type { SessionRecord } from '@itw-conformance-tool/database';

describe('PresentationSession model', () => {
  describe('createPresentationSession', () => {
    it('returns a pending session with the requested TTL', () => {
      const createdAt = 1_000_000;
      const session = createPresentationSession({
        id: 'sess-1',
        jwt: 'jwt-value',
        flowType: 'cross-device',
        ttlMs: 60_000,
        createdAtMs: createdAt
      });

      expect(session.id).toBe('sess-1');
      expect(session.state).toBe('pending');
      expect(session.flowType).toBe('cross-device');
      expect(session.jwt).toBe('jwt-value');
      expect(session.redirectUri).toBeNull();
      expect(session.values).toBeNull();
      expect(session.createdAt).toBe(createdAt);
      expect(session.expiresAt).toBe(createdAt + 60_000);
    });

    it('uses Date.now() when createdAtMs is omitted', () => {
      const before = Date.now();
      const session = createPresentationSession({
        id: 'sess-2',
        jwt: 'jwt',
        flowType: 'same-device',
        ttlMs: 10_000
      });
      const after = Date.now();

      expect(session.createdAt).toBeGreaterThanOrEqual(before);
      expect(session.createdAt).toBeLessThanOrEqual(after);
      expect(session.expiresAt - session.createdAt).toBe(10_000);
    });
  });

  describe('isTerminalState', () => {
    it.each(['verified', 'rejected', 'denied', 'expired'] as const)('treats %s as terminal', (state) => {
      expect(isTerminalState(state)).toBe(true);
    });

    it.each(['pending', 'checking'] as const)('does not treat %s as terminal', (state) => {
      expect(isTerminalState(state)).toBe(false);
    });
  });

  describe('mapToDbState', () => {
    it('maps pending and checking to db.pending', () => {
      expect(mapToDbState('pending')).toBe('pending');
      expect(mapToDbState('checking')).toBe('pending');
    });

    it('maps verified to db.completed', () => {
      expect(mapToDbState('verified')).toBe('completed');
    });

    it.each(['rejected', 'denied', 'expired'] as const)('maps %s to db.failed', (state) => {
      expect(mapToDbState(state)).toBe('failed');
    });
  });

  describe('serializeDetails / parseDetails', () => {
    it('round-trips persisted details', () => {
      const original = {
        rpState: 'checking' as const,
        flowType: 'cross-device' as const,
        redirectUri: 'https://wallet.example/cb',
        values: [{ given_name: 'Mario', family_name: null }],
        expiresAt: 1_700_000_000_000
      };

      const round = parseDetails(serializeDetails(original));

      expect(round).toEqual(original);
    });

    it('returns undefined when response is null', () => {
      expect(parseDetails(null)).toBeUndefined();
    });
  });

  describe('recordToPresentationSession', () => {
    it('builds a session from a SessionRecord with persisted details', () => {
      const record: SessionRecord = {
        id: 'sess-3',
        state: 'pending',
        requestObject: 'jwt-value',
        response: serializeDetails({
          rpState: 'checking',
          flowType: 'same-device',
          redirectUri: 'https://wallet.example/cb',
          values: null,
          expiresAt: 1_700_000_000_000
        }),
        createdAt: 1_699_999_000_000
      };

      const session = recordToPresentationSession(record);

      expect(session).toEqual({
        id: 'sess-3',
        state: 'checking',
        flowType: 'same-device',
        jwt: 'jwt-value',
        redirectUri: 'https://wallet.example/cb',
        values: null,
        expiresAt: 1_700_000_000_000,
        createdAt: 1_699_999_000_000
      });
    });

    it('throws when persisted details are missing', () => {
      const record: SessionRecord = {
        id: 'sess-4',
        state: 'pending',
        requestObject: 'jwt-value',
        response: null,
        createdAt: 0
      };

      expect(() => recordToPresentationSession(record)).toThrow(/persisted details/);
    });

    it('throws when JWT is missing', () => {
      const record: SessionRecord = {
        id: 'sess-5',
        state: 'pending',
        requestObject: null,
        response: serializeDetails({
          rpState: 'pending',
          flowType: 'cross-device',
          redirectUri: null,
          values: null,
          expiresAt: 0
        }),
        createdAt: 0
      };

      expect(() => recordToPresentationSession(record)).toThrow(/JWT/);
    });
  });

  describe('isExpiredNow', () => {
    it('returns true for non-terminal sessions past expiry', () => {
      expect(isExpiredNow({ state: 'pending', expiresAt: 100 }, 200)).toBe(true);
      expect(isExpiredNow({ state: 'checking', expiresAt: 100 }, 200)).toBe(true);
    });

    it('returns false for non-terminal sessions not yet expired', () => {
      expect(isExpiredNow({ state: 'pending', expiresAt: 200 }, 100)).toBe(false);
    });

    it('never considers terminal sessions expired', () => {
      expect(isExpiredNow({ state: 'verified', expiresAt: 0 }, 999)).toBe(false);
      expect(isExpiredNow({ state: 'rejected', expiresAt: 0 }, 999)).toBe(false);
      expect(isExpiredNow({ state: 'denied', expiresAt: 0 }, 999)).toBe(false);
      expect(isExpiredNow({ state: 'expired', expiresAt: 0 }, 999)).toBe(false);
    });
  });
});
