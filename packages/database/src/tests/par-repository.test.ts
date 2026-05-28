import { DatabaseSync } from 'node:sqlite';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { SqlitePARRepository } from '../par-repository.js';

describe('SqlitePARRepository', () => {
  let db: DatabaseSync;
  let repository: SqlitePARRepository;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    db.exec(`
      CREATE TABLE par_entries (
        request_uri TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        request_object TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
    repository = new SqlitePARRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  describe('Core CRUD Operations', () => {
    it('inserts and retrieves a PAR entry', async () => {
      const entry = {
        requestUri: 'urn:uuid:crud-1',
        clientId: 'client-1',
        requestObject: '{}',
        expiresAt: Date.now() + 10000
      };

      await repository.insert(entry);
      const retrieved = await repository.get(entry.requestUri);

      expect(retrieved).toBeDefined();
      expect(retrieved?.requestUri).toBe(entry.requestUri);
      expect(retrieved?.clientId).toBe(entry.clientId);
    });

    it('returns undefined and lazy-deletes if the entry is expired on get()', async () => {
      const entry = {
        requestUri: 'urn:uuid:crud-2',
        clientId: 'client-2',
        requestObject: '{}',
        expiresAt: Date.now() - 10000 // Expired 10 seconds ago
      };

      await repository.insert(entry);
      const retrieved = await repository.get(entry.requestUri);
      expect(retrieved).toBeUndefined();

      // Verify it was actually deleted from the DB
      const row = db.prepare('SELECT * FROM par_entries WHERE request_uri = ?').get(entry.requestUri);
      expect(row).toBeUndefined();
    });

    it('deletes an entry', async () => {
      const entry = {
        requestUri: 'urn:uuid:crud-3',
        clientId: 'client-3',
        requestObject: '{}',
        expiresAt: Date.now() + 10000
      };

      await repository.insert(entry);
      await repository.delete(entry.requestUri);
      const retrieved = await repository.get(entry.requestUri);

      expect(retrieved).toBeUndefined();
    });

    it('updates a PAR entry', async () => {
      const entry = {
        requestUri: 'urn:uuid:crud-4',
        clientId: 'client-4',
        requestObject: '{"test": true}',
        expiresAt: Date.now() + 10000
      };

      await repository.insert(entry);
      await repository.update(entry.requestUri, { clientId: 'client-updated' });

      const retrieved = await repository.get(entry.requestUri);
      expect(retrieved?.clientId).toBe('client-updated');
      expect(retrieved?.requestObject).toBe('{"test": true}'); // Unchanged fields remain
    });

    it('does nothing on update if no data is provided', async () => {
      const entry = {
        requestUri: 'urn:uuid:crud-5',
        clientId: 'client-5',
        requestObject: '{}',
        expiresAt: Date.now() + 10000
      };

      await repository.insert(entry);
      await repository.update(entry.requestUri, {}); // Empty update

      const retrieved = await repository.get(entry.requestUri);
      expect(retrieved?.clientId).toBe('client-5');
    });
  });

  describe('getByMrtdAuthSession', () => {
    it('retrieves a PAR entry by the nested mrtd_auth_session value', async () => {
      const requestUri = 'urn:uuid:123';
      const sessionId = 'session-123';
      const requestObject = JSON.stringify({
        mrtd_auth_session: { mrtd_auth_session: sessionId }
      });
      const expiresAt = Date.now() + 10000;

      await repository.insert({
        requestUri,
        clientId: 'client-1',
        requestObject,
        expiresAt
      });

      const entry = await repository.getByMrtdAuthSession(sessionId);
      expect(entry).toBeDefined();
      expect(entry?.requestUri).toBe(requestUri);
      expect(entry?.requestObject).toBe(requestObject);
    });

    it('deletes the row and returns undefined if the entry is expired', async () => {
      const requestUri = 'urn:uuid:123';
      const sessionId = 'session-123';
      const requestObject = JSON.stringify({
        mrtd_auth_session: { mrtd_auth_session: sessionId }
      });
      const expiresAt = Date.now() - 10000; // Expired 10 seconds ago

      await repository.insert({
        requestUri,
        clientId: 'client-1',
        requestObject,
        expiresAt
      });

      const entry = await repository.getByMrtdAuthSession(sessionId);
      expect(entry).toBeUndefined();

      const row = db.prepare('SELECT * FROM par_entries WHERE request_uri = ?').get(requestUri);
      expect(row).toBeUndefined();
    });

    it('returns undefined if no matching session is found', async () => {
      const entry = await repository.getByMrtdAuthSession('non-existent-session');
      expect(entry).toBeUndefined();
    });
  });
});
