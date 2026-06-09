import type { IConformanceSessionRepository } from '../models/types.js';

const DEFAULT_TTL_SECONDS = 3600;
const DEFAULT_INTERVAL_MS = 60_000;

export interface RunConformanceCleanupOptions {
  now?: Date;
  repository: IConformanceSessionRepository;
  ttlSeconds?: number;
}

export interface StartConformanceCleanupJobOptions {
  intervalMs?: number;
  logger?: {
    info?: (meta: Record<string, unknown>, message: string) => void;
    error?: (meta: Record<string, unknown>, message: string) => void;
  };
  now?: () => Date;
  repository: IConformanceSessionRepository;
  ttlSeconds?: number;
}

export async function runConformanceCleanup(options: RunConformanceCleanupOptions): Promise<number> {
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const now = options.now ?? new Date();
  const cutoffIso = new Date(now.getTime() - ttlSeconds * 1000).toISOString();

  return options.repository.markOpenSessionsIncompleteOlderThan(cutoffIso);
}

export function startConformanceCleanupJob(options: StartConformanceCleanupJobOptions): () => void {
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const now = options.now ?? (() => new Date());

  let running = false;

  const tick = async () => {
    if (running) {
      return;
    }

    running = true;
    try {
      const updated = await runConformanceCleanup({
        now: now(),
        repository: options.repository,
        ttlSeconds
      });

      if (updated > 0) {
        options.logger?.info?.({ updated }, 'Conformance cleanup marked stale OPEN sessions as INCOMPLETE');
      }
    } catch (error) {
      options.logger?.error?.({ err: error }, 'Conformance cleanup job failed');
    } finally {
      running = false;
    }
  };

  const timer = setInterval(() => {
    void tick();
  }, intervalMs);

  // Cleanup must not keep the event loop alive on process shutdown.
  timer.unref();

  return () => {
    clearInterval(timer);
  };
}
