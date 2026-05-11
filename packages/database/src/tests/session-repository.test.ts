import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DatabaseClient } from '../client.js';
import { SqliteSessionRepository } from '../session-repository.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-session-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('SqliteSessionRepository', () => {
  let client: DatabaseClient;
  let repo: SqliteSessionRepository;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    repo = new SqliteSessionRepository(client.db);
  });

  afterEach(() => {
    client.close();
  });

  it('insert creates a session with pending state', async () => {
    await repo.insert('session-1', 'jwt.request.object');
    const result = await repo.get('session-1');
    expect(result?.id).toBe('session-1');
    expect(result?.state).toBe('pending');
    expect(result?.requestObject).toBe('jwt.request.object');
    expect(result?.response).toBeNull();
    expect(result?.createdAt).toBeTypeOf('number');
  });

  it('insert without requestObject stores null', async () => {
    await repo.insert('session-2');
    const result = await repo.get('session-2');
    expect(result?.requestObject).toBeNull();
  });

  it('get returns undefined for nonexistent session', async () => {
    const result = await repo.get('nonexistent');
    expect(result).toBeUndefined();
  });

  it('update changes state and response', async () => {
    await repo.insert('session-3');
    await repo.update('session-3', 'completed', JSON.stringify({ vp_token: 'xxx' }));
    const result = await repo.get('session-3');
    expect(result?.state).toBe('completed');
    expect(result?.response).toBe(JSON.stringify({ vp_token: 'xxx' }));
  });

  it('update without response sets response to null', async () => {
    await repo.insert('session-4');
    await repo.update('session-4', 'failed');
    const result = await repo.get('session-4');
    expect(result?.state).toBe('failed');
    expect(result?.response).toBeNull();
  });

  it('delete removes the session', async () => {
    await repo.insert('session-5');
    await repo.delete('session-5');
    const result = await repo.get('session-5');
    expect(result).toBeUndefined();
  });

  it('delete is a no-op for nonexistent session', async () => {
    await expect(repo.delete('ghost')).resolves.not.toThrow();
  });

  it('supports all SessionState values', async () => {
    const states = ['pending', 'completed', 'failed'] as const;
    for (const state of states) {
      const id = `session-state-${state}`;
      await repo.insert(id);
      await repo.update(id, state);
      const result = await repo.get(id);
      expect(result?.state).toBe(state);
    }
  });
});
