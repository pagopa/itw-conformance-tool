import { describe, it, expect, beforeEach } from 'vitest';

import { parseDetails, serializeDetails } from '../../models/presentation-session.js';
import { SessionService } from '../../services/session-service.js';

import type { ISessionRepository, SessionRecord, SessionState } from '@itw-conformance-tool/database';

interface InMemoryStore {
  records: Map<string, SessionRecord>;
  repo: ISessionRepository;
}

function makeInMemoryRepository(): InMemoryStore {
  const records = new Map<string, SessionRecord>();
  const repo: ISessionRepository = {
    async insert(id: string, requestObject?: string): Promise<void> {
      records.set(id, {
        id,
        state: 'pending',
        requestObject: requestObject ?? null,
        response: null,
        createdAt: Date.now()
      });
    },
    async get(id: string): Promise<SessionRecord | undefined> {
      return records.get(id);
    },
    async update(id: string, state: SessionState, response?: string): Promise<void> {
      const existing = records.get(id);
      if (!existing) {
        throw new Error(`not found: ${id}`);
      }
      records.set(id, {
        ...existing,
        state,
        response: response ?? existing.response
      });
    },
    async delete(id: string): Promise<void> {
      records.delete(id);
    }
  };
  return { records, repo };
}

describe('SessionService', () => {
  let store: InMemoryStore;
  let service: SessionService;

  beforeEach(() => {
    store = makeInMemoryRepository();
    service = new SessionService(store.repo);
  });

  describe('create', () => {
    it('persists a pending session with the requested TTL', async () => {
      const before = Date.now();
      const session = await service.create({
        id: 'sess-1',
        jwt: 'jwt-value',
        flowType: 'cross-device',
        ttlMs: 60_000
      });

      expect(session.id).toBe('sess-1');
      expect(session.state).toBe('pending');
      expect(session.flowType).toBe('cross-device');
      expect(session.jwt).toBe('jwt-value');
      expect(session.expiresAt).toBeGreaterThanOrEqual(before + 60_000);

      const record = store.records.get('sess-1');
      expect(record?.state).toBe('pending');
      expect(record?.requestObject).toBe('jwt-value');
      const details = parseDetails(record?.response ?? null);
      expect(details?.rpState).toBe('pending');
      expect(details?.flowType).toBe('cross-device');
      expect(details?.redirectUri).toBeNull();
      expect(details?.values).toBeNull();
    });

    it('uses the default TTL (5 minutes) when omitted', async () => {
      const before = Date.now();
      const session = await service.create({
        id: 'sess-2',
        jwt: 'jwt',
        flowType: 'same-device'
      });

      expect(session.expiresAt - before).toBeGreaterThanOrEqual(5 * 60 * 1000 - 50);
      expect(session.expiresAt - before).toBeLessThan(5 * 60 * 1000 + 50);
    });
  });

  describe('get', () => {
    it('returns undefined when the session does not exist', async () => {
      expect(await service.get('ghost')).toBeUndefined();
    });

    it('returns the rich session for an active record', async () => {
      await service.create({ id: 'sess-3', jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });

      const session = await service.get('sess-3');

      expect(session?.state).toBe('pending');
      expect(session?.flowType).toBe('cross-device');
      expect(session?.jwt).toBe('jwt');
    });

    it('lazily transitions an expired non-terminal session to expired', async () => {
      const id = 'sess-4';
      // Seed a record whose expiry is already in the past.
      const past = Date.now() - 10_000;
      store.records.set(id, {
        id,
        state: 'pending',
        requestObject: 'jwt',
        response: serializeDetails({
          rpState: 'checking',
          flowType: 'cross-device',
          redirectUri: null,
          values: null,
          expiresAt: past
        }),
        createdAt: past - 1000
      });

      const session = await service.get(id);

      expect(session?.state).toBe('expired');
      const persisted = store.records.get(id);
      expect(persisted?.state).toBe('failed');
      const details = parseDetails(persisted?.response ?? null);
      expect(details?.rpState).toBe('expired');
    });

    it('does not transition a terminal session that has passed expiry', async () => {
      const id = 'sess-5';
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });
      await service.update(id, 'verified', { redirectUri: 'https://wallet/cb' });

      // Mutate record to look stale
      const record = store.records.get(id);
      if (record) {
        const details = parseDetails(record.response);
        if (details) {
          details.expiresAt = Date.now() - 10_000;
          store.records.set(id, { ...record, response: serializeDetails(details) });
        }
      }

      const session = await service.get(id);
      expect(session?.state).toBe('verified');
    });
  });

  describe('update', () => {
    it('moves a pending session to checking and preserves details', async () => {
      const id = 'sess-6';
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });

      await service.update(id, 'checking');

      const session = await service.get(id);
      expect(session?.state).toBe('checking');
      expect(store.records.get(id)?.state).toBe('pending');
    });

    it('moves to verified with redirectUri and values, mapping db state to completed', async () => {
      const id = 'sess-7';
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });

      await service.update(id, 'verified', {
        redirectUri: 'https://wallet.example/cb',
        values: [{ given_name: 'Mario' }]
      });

      const session = await service.get(id);
      expect(session?.state).toBe('verified');
      expect(session?.redirectUri).toBe('https://wallet.example/cb');
      expect(session?.values).toEqual([{ given_name: 'Mario' }]);
      expect(store.records.get(id)?.state).toBe('completed');
    });

    it.each(['rejected', 'denied', 'expired'] as const)('maps %s to db.failed', async (rpState) => {
      const id = `sess-${rpState}`;
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });

      await service.update(id, rpState);

      expect(store.records.get(id)?.state).toBe('failed');
      expect((await service.get(id))?.state).toBe(rpState);
    });

    it('is a no-op when the session is already in a terminal state', async () => {
      const id = 'sess-terminal';
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });
      await service.update(id, 'verified', { redirectUri: 'https://wallet/cb' });

      await service.update(id, 'rejected');

      const session = await service.get(id);
      expect(session?.state).toBe('verified');
    });

    it('throws when the session does not exist', async () => {
      await expect(service.update('ghost', 'checking')).rejects.toThrow(/not found/);
    });
  });

  describe('delete', () => {
    it('removes the session', async () => {
      const id = 'sess-del';
      await service.create({ id, jwt: 'jwt', flowType: 'cross-device', ttlMs: 60_000 });

      await service.delete(id);

      expect(store.records.has(id)).toBe(false);
      expect(await service.get(id)).toBeUndefined();
    });
  });
});
