import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DatabaseClient } from '../client.js';
import { SqlitePARRepository } from '../par-repository.js';

import type { PAREntry } from '../interfaces.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-par-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

function makeEntry(overrides: Partial<PAREntry> = {}): PAREntry {
  return {
    requestUri: 'urn:test:1',
    clientId: 'client-1',
    requestObject: JSON.stringify({ foo: 'bar' }),
    expiresAt: Date.now() + 60_000,
    ...overrides
  };
}

describe('SqlitePARRepository', () => {
  let client: DatabaseClient;
  let repo: SqlitePARRepository;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    repo = new SqlitePARRepository(client.db);
  });

  afterEach(() => {
    client.close();
  });

  it('insert and get by requestUri', async () => {
    const entry = makeEntry();
    await repo.insert(entry);
    const result = await repo.get(entry.requestUri);
    expect(result?.requestUri).toBe(entry.requestUri);
    expect(result?.clientId).toBe(entry.clientId);
  });

  it('get returns undefined for unknown requestUri', async () => {
    const result = await repo.get('urn:unknown');
    expect(result).toBeUndefined();
  });

  it('get returns undefined for expired entry (lazy expiry)', async () => {
    const entry = makeEntry({ expiresAt: Date.now() - 2000 });
    await repo.insert(entry);
    const result = await repo.get(entry.requestUri);
    expect(result).toBeUndefined();
  });

  it('delete removes the entry', async () => {
    const entry = makeEntry();
    await repo.insert(entry);
    await repo.delete(entry.requestUri);
    const result = await repo.get(entry.requestUri);
    expect(result).toBeUndefined();
  });

  it('update changes requestObject', async () => {
    const entry = makeEntry();
    await repo.insert(entry);
    await repo.update(entry.requestUri, { requestObject: JSON.stringify({ updated: true }) });
    const result = await repo.get(entry.requestUri);
    expect(result?.requestObject).toBe(JSON.stringify({ updated: true }));
  });

  it('update with empty data is a no-op', async () => {
    const entry = makeEntry();
    await repo.insert(entry);
    await expect(repo.update(entry.requestUri, {})).resolves.not.toThrow();
  });
});
