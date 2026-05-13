import type { ISessionRepository, SessionRecord, SessionState } from './interfaces.js';
import type { DatabaseSync } from 'node:sqlite';

type SessionRow = {
  id: string;
  state: string;
  request_object: string | null;
  response: string | null;
  created_at: number;
};

function rowToRecord(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    state: row.state as SessionState,
    requestObject: row.request_object,
    response: row.response,
    createdAt: row.created_at
  };
}

export class SqliteSessionRepository implements ISessionRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async delete(id: string): Promise<void> {
    this.db.prepare('DELETE FROM presentation_sessions WHERE id = ?').run(id);
  }

  async get(id: string): Promise<SessionRecord | undefined> {
    const row = this.db.prepare('SELECT * FROM presentation_sessions WHERE id = ?').get(id) as SessionRow | undefined;

    return row ? rowToRecord(row) : undefined;
  }

  async insert(id: string, requestObject?: string): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO presentation_sessions (id, state, request_object, response, created_at)
         VALUES (?, 'pending', ?, NULL, ?)`
      )
      .run(id, requestObject ?? null, Date.now());
  }

  async update(id: string, state: SessionState, response?: string): Promise<void> {
    this.db
      .prepare(`UPDATE presentation_sessions SET state = ?, response = ? WHERE id = ?`)
      .run(state, response ?? null, id);
  }
}
