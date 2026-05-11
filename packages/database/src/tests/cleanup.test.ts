import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { DatabaseClient } from '../client.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-cleanup-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('DatabaseClient cleanup interval', () => {
  let client: DatabaseClient;

  beforeEach(() => {
    vi.useFakeTimers();
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 1_000 });
  });

  afterEach(() => {
    vi.useRealTimers();
    client.close();
  });

  it('purges expired rows after the cleanup interval fires', () => {
    const past = Date.now() - 2000;
    const future = Date.now() + 60_000;

    client.db.prepare('INSERT INTO nonces (value, expires_at) VALUES (?, ?)').run('old', past);
    client.db.prepare('INSERT INTO nonces (value, expires_at) VALUES (?, ?)').run('new', future);

    // Advance time by 1 second to trigger the interval
    vi.advanceTimersByTime(1_001);

    const rows = client.db.prepare('SELECT value FROM nonces').all() as { value: string }[];
    expect(rows.map(r => r.value)).not.toContain('old');
    expect(rows.map(r => r.value)).toContain('new');
  });

  it('close() stops the cleanup interval', () => {
    const purge = vi.spyOn(client, 'purgeExpired');
    client.close();
    vi.advanceTimersByTime(10_000);
    expect(purge).not.toHaveBeenCalled();
  });
});
