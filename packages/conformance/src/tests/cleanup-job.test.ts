import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { runConformanceCleanup, startConformanceCleanupJob } from '../jobs/cleanup.js';
import { SqliteConformanceSessionRepository } from '../repository.js';

function makeTmpDir(): string {
  return join(tmpdir(), `itw-conformance-cleanup-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

describe('conformance cleanup job', () => {
  let client: DatabaseClient | undefined;

  afterEach(() => {
    client?.close();
    client = undefined;
    vi.restoreAllMocks();
  });

  it('marks stale OPEN sessions as INCOMPLETE', async () => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    const repo = new SqliteConformanceSessionRepository(client.db);

    const now = new Date('2026-06-09T12:00:00.000Z');
    const staleStartedAt = new Date(now.getTime() - 3601 * 1000).toISOString();
    const freshStartedAt = new Date(now.getTime() - 120 * 1000).toISOString();

    await repo.create({ checks: [], sessionId: 'stale-open', startedAt: staleStartedAt, status: 'OPEN' });
    await repo.create({ checks: [], sessionId: 'fresh-open', startedAt: freshStartedAt, status: 'OPEN' });
    await repo.create({
      checks: [],
      closedAt: freshStartedAt,
      sessionId: 'already-passed',
      startedAt: staleStartedAt,
      status: 'PASSED'
    });

    const updated = await runConformanceCleanup({ now, repository: repo, ttlSeconds: 3600 });
    expect(updated).toBe(1);

    const stale = await repo.get('stale-open');
    const fresh = await repo.get('fresh-open');
    const passed = await repo.get('already-passed');

    expect(stale?.status).toBe('INCOMPLETE');
    expect(stale?.closedAt).toBeDefined();
    expect(fresh?.status).toBe('OPEN');
    expect(passed?.status).toBe('PASSED');
  });

  it('runs periodically and can be stopped', async () => {
    client = new DatabaseClient({ dataDir: makeTmpDir(), cleanupIntervalMs: 999_999 });
    const repo = new SqliteConformanceSessionRepository(client.db);

    const logger = {
      error: vi.fn(),
      info: vi.fn()
    };

    const now = new Date('2026-06-09T12:00:00.000Z');
    await repo.create({
      checks: [],
      sessionId: 'stale-open-timer',
      startedAt: new Date(now.getTime() - 3700 * 1000).toISOString(),
      status: 'OPEN'
    });

    const stop = startConformanceCleanupJob({
      intervalMs: 10,
      logger,
      now: () => now,
      repository: repo,
      ttlSeconds: 3600
    });

    await new Promise((resolve) => setTimeout(resolve, 40));
    stop();

    const stale = await repo.get('stale-open-timer');
    expect(stale?.status).toBe('INCOMPLETE');
    expect(logger.info).toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });
});
