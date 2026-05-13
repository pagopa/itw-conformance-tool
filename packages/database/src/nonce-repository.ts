import type { INonceRepository } from './interfaces.js';
import type { DatabaseSync } from 'node:sqlite';

export class SqliteNonceRepository implements INonceRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async delete(value: string): Promise<void> {
    this.db.prepare('DELETE FROM nonces WHERE value = ?').run(value);
  }

  async get(value: string): Promise<string | undefined> {
    const row = this.db.prepare('SELECT value, expires_at FROM nonces WHERE value = ?').get(value) as
      | { value: string; expires_at: number }
      | undefined;

    if (!row) {
      return undefined;
    }

    const nowMs = (this.db.prepare("SELECT unixepoch('now') * 1000 AS now").get() as { now: number }).now;
    if (row.expires_at < nowMs) {
      this.db.prepare('DELETE FROM nonces WHERE value = ?').run(value);
      return undefined;
    }

    return row.value;
  }

  async insert(value: string, expiresAtMs: number): Promise<void> {
    this.db.prepare('INSERT OR REPLACE INTO nonces (value, expires_at, used) VALUES (?, ?, 0)').run(value, expiresAtMs);
  }
}
