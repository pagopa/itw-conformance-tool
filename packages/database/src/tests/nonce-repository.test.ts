import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DatabaseClient } from '../client.js';
import { SqliteNonceRepository } from '../nonce-repository.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-nonce-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('SqliteNonceRepository', () => {
  let client: DatabaseClient;
  let repo: SqliteNonceRepository;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    repo = new SqliteNonceRepository(client.db);
  });

  afterEach(() => {
    client.close();
  });

  it('insert and get returns the nonce value', async () => {
    const future = Date.now() + 60_000;
    await repo.insert('abc123', future);
    const result = await repo.get('abc123');
    expect(result).toBe('abc123');
  });

  it('get returns undefined for unknown nonce', async () => {
    const result = await repo.get('nonexistent');
    expect(result).toBeUndefined();
  });

  it('get returns undefined for expired nonce (lazy expiry)', async () => {
    const past = Date.now() - 2000;
    await repo.insert('stale', past);
    const result = await repo.get('stale');
    expect(result).toBeUndefined();
  });

  it('delete removes the nonce', async () => {
    const future = Date.now() + 60_000;
    await repo.insert('to-delete', future);
    await repo.delete('to-delete');
    const result = await repo.get('to-delete');
    expect(result).toBeUndefined();
  });

  it('delete is a no-op for nonexistent nonce', async () => {
    await expect(repo.delete('ghost')).resolves.not.toThrow();
  });

  it('consume returns true and removes a valid nonce', async () => {
    const future = Date.now() + 60_000;
    await repo.insert('to-consume', future);

    await expect(repo.consume('to-consume')).resolves.toBe(true);
    await expect(repo.get('to-consume')).resolves.toBeUndefined();
  });

  it('consume returns false for expired nonce and removes it', async () => {
    const past = Date.now() - 2000;
    await repo.insert('expired-consume', past);

    await expect(repo.consume('expired-consume')).resolves.toBe(false);
    await expect(repo.get('expired-consume')).resolves.toBeUndefined();
  });

  it('consume returns false for unknown nonce', async () => {
    await expect(repo.consume('missing-consume')).resolves.toBe(false);
  });

  it('insert twice with same value replaces the row', async () => {
    const future = Date.now() + 60_000;
    await repo.insert('dup', future);
    await repo.insert('dup', future + 1);
    const result = await repo.get('dup');
    expect(result).toBe('dup');
  });
});
