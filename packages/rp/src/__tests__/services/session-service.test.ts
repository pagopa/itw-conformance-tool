import { describe, it, expect, vi } from 'vitest';

import { SessionService } from '../../services/session-service.js';

import type { SessionRepository } from '../../repositories.js';

describe('SessionService', () => {
  describe('create', () => {
    it('should create a new session', async () => {
      const mockRepository: SessionRepository = {
        create: vi.fn(),
        findById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn()
      };

      const service = new SessionService(mockRepository);
      const sessionId = await service.create({ sessionId: 'test-session' });

      expect(sessionId).toBe('test-session');
      expect(mockRepository.create).toHaveBeenCalled();

      const createdSession = vi.mocked(mockRepository.create).mock.calls[0][0];
      expect(createdSession.sessionId).toBe('test-session');
      expect(createdSession.state).toBe('pending');
    });

    it('should respect custom TTL', async () => {
      const mockRepository: SessionRepository = {
        create: vi.fn(),
        findById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn()
      };

      const service = new SessionService(mockRepository);
      await service.create({ sessionId: 'test-session', ttlSeconds: 600 });

      const createdSession = vi.mocked(mockRepository.create).mock.calls[0][0];
      const ttlMs = createdSession.expiresAt.getTime() - createdSession.createdAt.getTime();

      expect(ttlMs).toBeGreaterThan(599000);
      expect(ttlMs).toBeLessThan(601000);
    });
  });

  describe('get', () => {
    it('should retrieve a session', async () => {
      const mockSession = {
        sessionId: 'test-session',
        state: 'pending' as const,
        flowType: 'presentation' as const,
        values: [],
        createdAt: new Date(),
        expiresAt: new Date()
      };

      const mockRepository: SessionRepository = {
        create: vi.fn(),
        findById: vi.fn().mockResolvedValue(mockSession),
        update: vi.fn(),
        delete: vi.fn()
      };

      const service = new SessionService(mockRepository);
      const session = await service.get('test-session');

      expect(session).toEqual(mockSession);
      expect(mockRepository.findById).toHaveBeenCalledWith('test-session');
    });
  });

  describe('update', () => {
    it('should update session state and details', async () => {
      const mockRepository: SessionRepository = {
        create: vi.fn(),
        findById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn()
      };

      const service = new SessionService(mockRepository);
      await service.update('test-session', 'verified', {
        redirectUri: 'http://example.com/callback',
        values: [{ name: 'John' }]
      });

      expect(mockRepository.update).toHaveBeenCalledWith(
        'test-session',
        'verified',
        expect.objectContaining({
          redirectUri: 'http://example.com/callback',
          values: [{ name: 'John' }]
        })
      );
    });
  });

  describe('delete', () => {
    it('should delete a session', async () => {
      const mockRepository: SessionRepository = {
        create: vi.fn(),
        findById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn()
      };

      const service = new SessionService(mockRepository);
      await service.delete('test-session');

      expect(mockRepository.delete).toHaveBeenCalledWith('test-session');
    });
  });
});
