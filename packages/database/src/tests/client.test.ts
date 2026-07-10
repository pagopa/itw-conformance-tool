import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { DatabaseClient } from '../client.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-db-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('DatabaseClient', () => {
  let client: DatabaseClient;

  beforeEach(() => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
  });

  afterEach(() => {
    client.close();
  });

  it('creates all required tables on init', () => {
    const tables = client.db.prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`).all() as {
      name: string;
    }[];
    const names = tables.map((t) => t.name);
    expect(names).toContain('nonces');
    expect(names).toContain('par_entries');
    expect(names).toContain('presentation_sessions');
    expect(names).toContain('conformance_sessions');
    expect(names).toContain('conformance_events');
  });

  it('is idempotent — init twice on the same dataDir does not throw', () => {
    const sharedDir = makeTmpDir();
    const client1 = new DatabaseClient({ dataDir: sharedDir, cleanupIntervalMs: 999_999 });
    client1.close();
    expect(() => {
      const client2 = new DatabaseClient({ dataDir: sharedDir, cleanupIntervalMs: 999_999 });
      client2.close();
    }).not.toThrow();
  });

  it('purgeExpired removes rows with past expires_at', () => {
    const { now } = client.db.prepare("SELECT unixepoch('now') * 1000 AS now").get() as { now: number };
    const past = now - 1_000;
    const future = now + 60_000;
    client.db.prepare('INSERT INTO nonces (value, expires_at) VALUES (?, ?)').run('expired', past);
    client.db.prepare('INSERT INTO nonces (value, expires_at) VALUES (?, ?)').run('valid', future);

    client.purgeExpired();

    const rows = client.db.prepare('SELECT value FROM nonces').all() as { value: string }[];
    expect(rows.map((r) => r.value)).toEqual(['valid']);
  });

  it('close() can be called multiple times without error', () => {
    expect(() => {
      client.close();
      client.close();
    }).not.toThrow();
  });
});
