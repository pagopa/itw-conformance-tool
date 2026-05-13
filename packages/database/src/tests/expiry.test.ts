import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DatabaseClient } from '../client.js';
import { SqliteNonceRepository } from '../nonce-repository.js';
import { SqlitePARRepository } from '../par-repository.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-expiry-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('Lazy expiry on reads', () => {
  let client: DatabaseClient;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
  });

  afterEach(() => {
    client.close();
  });

  it('expired nonces are removed on get()', async () => {
    const repo = new SqliteNonceRepository(client.db);
    await repo.insert('expired-nonce', Date.now() - 2000);
    await repo.insert('valid-nonce', Date.now() + 60_000);

    // Trigger lazy expiry via get()
    await repo.get('expired-nonce');

    const rows = client.db.prepare('SELECT value FROM nonces').all() as { value: string }[];
    expect(rows.map((r) => r.value)).not.toContain('expired-nonce');
    expect(rows.map((r) => r.value)).toContain('valid-nonce');
  });

  it('expired par_entries are removed on get()', async () => {
    const repo = new SqlitePARRepository(client.db);
    await repo.insert({
      requestUri: 'urn:expired',
      clientId: 'c1',
      requestObject: '{}',
      expiresAt: Date.now() - 2000
    });
    await repo.insert({
      requestUri: 'urn:valid',
      clientId: 'c1',
      requestObject: '{}',
      expiresAt: Date.now() + 60_000
    });

    // Trigger lazy expiry via get()
    await repo.get('urn:expired');

    const rows = client.db.prepare('SELECT request_uri FROM par_entries').all() as { request_uri: string }[];
    expect(rows.map((r) => r.request_uri)).not.toContain('urn:expired');
    expect(rows.map((r) => r.request_uri)).toContain('urn:valid');
  });
});
