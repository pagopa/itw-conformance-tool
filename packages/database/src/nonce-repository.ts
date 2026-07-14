import type { DatabaseClient } from './client.js';
import type { INonceRepository } from './interfaces.js';

export class SqliteNonceRepository implements INonceRepository {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async consume(value: string): Promise<boolean> {
    const nowMs = this.db.get<{ now: number }>("SELECT unixepoch('now') * 1000 AS now")?.now ?? Date.now();
    const result = this.db.run('DELETE FROM nonces WHERE value = ? AND expires_at >= ?', [value, nowMs]);

    if (result.changes > 0) {
      return true;
    }

    // Lazy cleanup for expired entries when consume fails.
    this.db.run('DELETE FROM nonces WHERE value = ?', [value]);
    return false;
  }

  async delete(value: string): Promise<void> {
    this.db.run('DELETE FROM nonces WHERE value = ?', [value]);
  }

  async get(value: string): Promise<string | undefined> {
    const row = this.db.get<{ value: string; expires_at: number }>(
      'SELECT value, expires_at FROM nonces WHERE value = ?',
      [value]
    );

    if (!row) {
      return undefined;
    }

    const nowMs = this.db.get<{ now: number }>("SELECT unixepoch('now') * 1000 AS now")?.now ?? Date.now();
    if (row.expires_at < nowMs) {
      this.db.run('DELETE FROM nonces WHERE value = ?', [value]);
      return undefined;
    }

    return row.value;
  }

  async insert(value: string, expiresAtMs: number): Promise<void> {
    this.db.run('INSERT OR REPLACE INTO nonces (value, expires_at, used) VALUES (?, ?, 0)', [value, expiresAtMs]);
  }
}
