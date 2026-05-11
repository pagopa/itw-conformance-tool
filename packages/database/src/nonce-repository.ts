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
    // Lazy expiry: remove stale rows before reading
    this.db.exec('DELETE FROM nonces WHERE expires_at < unixepoch(\'now\') * 1000');

    const row = this.db.prepare('SELECT value FROM nonces WHERE value = ?').get(value) as
      | { value: string }
      | undefined;

    return row?.value;
  }

  async insert(value: string, expiresAtMs: number): Promise<void> {
    this.db
      .prepare('INSERT OR REPLACE INTO nonces (value, expires_at, used) VALUES (?, ?, 0)')
      .run(value, expiresAtMs);
  }
}
