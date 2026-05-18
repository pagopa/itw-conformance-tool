import { existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import Database from 'better-sqlite3';

import type { NonceRepository } from '@itw-conformance-tool/rp';

/**
 * SQLite-backed nonce repository for CSRF/replay attack prevention.
 * Shares the same database file as presentation sessions.
 */
export class SqliteNonceRepository implements NonceRepository {
  private db: Database.Database;

  constructor(dataDir: string) {
    // Ensure data directory exists
    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = resolve(dataDir, 'itw-conformance-tool.db');
    this.db = new Database(dbPath);

    // Enable foreign keys
    this.db.pragma('foreign_keys = ON');

    // Initialize schema
    this.initializeSchema();
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rp_nonces (
        nonce TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_rp_nonces_expires_at ON rp_nonces(expires_at);
    `);
  }

  /**
   * Store a nonce with a TTL
   */
  async store(nonce: string, ttlSeconds: number): Promise<void> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;

    const stmt = this.db.prepare(`
      INSERT INTO rp_nonces (nonce, created_at, expires_at)
      VALUES (?, ?, ?)
    `);

    stmt.run(nonce, now, expiresAt);
  }

  /**
   * Consume a nonce (verify and remove it)
   */
  async consume(nonce: string): Promise<boolean> {
    const stmt = this.db.prepare(`
      SELECT nonce FROM rp_nonces
      WHERE nonce = ? AND expires_at > ?
    `);

    const result = stmt.get(nonce, Date.now()) as { nonce: string } | undefined;

    if (!result) {
      return false;
    }

    // Delete the nonce (one-time use)
    const deleteStmt = this.db.prepare('DELETE FROM rp_nonces WHERE nonce = ?');
    deleteStmt.run(nonce);

    return true;
  }

  /**
   * Clean up expired nonces
   */
  async deleteExpired(): Promise<number> {
    const stmt = this.db.prepare('DELETE FROM rp_nonces WHERE expires_at <= ?');
    const result = stmt.run(Date.now());
    return result.changes;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
  }
}
