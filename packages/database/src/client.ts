import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type DatabaseClientOptions = {
  /** Absolute path to the data directory. The database file will be created as `itw.db` inside it. */
  dataDir: string;
  /** Cleanup interval in milliseconds. Defaults to 60 000 (60 seconds). */
  cleanupIntervalMs?: number;
};

const DDL = `
  CREATE TABLE IF NOT EXISTS nonces (
    value      TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS par_entries (
    request_uri    TEXT    PRIMARY KEY,
    client_id      TEXT    NOT NULL,
    request_object TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS presentation_sessions (
    id             TEXT    PRIMARY KEY,
    state          TEXT    NOT NULL CHECK(state IN ('pending', 'completed', 'failed')),
    request_object TEXT,
    response       TEXT,
    created_at     INTEGER NOT NULL
  );
`;

export class DatabaseClient {
  readonly db: DatabaseSync;
  private cleanupTimer: NodeJS.Timeout | undefined;
  private isOpen = true;

  constructor({ dataDir, cleanupIntervalMs = 60_000 }: DatabaseClientOptions) {
    mkdirSync(dataDir, { recursive: true });
    const dbPath = join(dataDir, 'itw.db');
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec(DDL);
    this.startCleanup(cleanupIntervalMs);
  }

  /** Removes all expired rows from nonces and par_entries. */
  purgeExpired(): void {
    this.db.exec('DELETE FROM nonces WHERE expires_at < unixepoch(\'now\') * 1000');
    this.db.exec('DELETE FROM par_entries WHERE expires_at < unixepoch(\'now\') * 1000');
  }

  close(): void {
    if (!this.isOpen) return;
    this.isOpen = false;
    if (this.cleanupTimer !== undefined) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.db.close();
  }

  private startCleanup(intervalMs: number): void {
    this.cleanupTimer = setInterval(() => {
      if (!this.isOpen) return;
      this.purgeExpired();
    }, intervalMs);
    // Do not keep the process alive solely for cleanup
    this.cleanupTimer.unref();
  }
}
