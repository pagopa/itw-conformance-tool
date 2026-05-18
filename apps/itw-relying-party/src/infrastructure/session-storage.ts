import { existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

import Database from 'better-sqlite3';

import type {
  PresentationSession,
  PresentationSessionState,
  PresentationSessionDetails,
  SessionRepository
} from '@itw-conformance-tool/rp';

/**
 * SQLite-backed session repository for presentation session state.
 * Shares the same database file as the issuer in data_dir.
 */
export class SqliteSessionRepository implements SessionRepository {
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
      CREATE TABLE IF NOT EXISTS rp_presentation_sessions (
        sessionId TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        data TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_rp_sessions_expires_at ON rp_presentation_sessions(expires_at);
    `);
  }

  /**
   * Create a new presentation session
   */
  async create(session: PresentationSession): Promise<void> {
    const now = Date.now();
    const expiresAt = session.expiresAt?.getTime() ?? now + 24 * 60 * 60 * 1000;

    const stmt = this.db.prepare(`
      INSERT INTO rp_presentation_sessions (sessionId, state, created_at, expires_at, data)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(session.sessionId, session.state, now, expiresAt, JSON.stringify(session));
  }

  /**
   * Retrieve a presentation session by ID
   */
  async findById(id: string): Promise<PresentationSession | null> {
    const stmt = this.db.prepare(`
      SELECT data FROM rp_presentation_sessions
      WHERE sessionId = ? AND expires_at > ?
    `);

    const result = stmt.get(id, Date.now()) as { data: string } | undefined;

    if (!result) {
      return null;
    }

    return JSON.parse(result.data) as PresentationSession;
  }

  /**
   * Update a presentation session state and optional details
   */
  async update(id: string, state: PresentationSessionState, details?: PresentationSessionDetails): Promise<void> {
    const session = await this.findById(id);
    if (!session) {
      throw new Error(`Session ${id} not found`);
    }

    const updated: PresentationSession = {
      ...session,
      state,
      redirectUri: details?.redirectUri ?? session.redirectUri,
      values: details?.values ?? session.values
    };

    const stmt = this.db.prepare(`
      UPDATE rp_presentation_sessions
      SET state = ?, data = ?
      WHERE sessionId = ?
    `);

    stmt.run(state, JSON.stringify(updated), id);
  }

  /**
   * Delete a presentation session
   */
  async delete(id: string): Promise<void> {
    const stmt = this.db.prepare('DELETE FROM rp_presentation_sessions WHERE sessionId = ?');
    stmt.run(id);
  }

  /**
   * Clean up expired sessions
   */
  async deleteExpired(): Promise<number> {
    const stmt = this.db.prepare('DELETE FROM rp_presentation_sessions WHERE expires_at <= ?');
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
