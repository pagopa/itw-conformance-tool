import type { DatabaseClient } from './client.js';
import type { ISessionRepository, SessionRecord, SessionState } from './interfaces.js';

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
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async delete(id: string): Promise<void> {
    this.db.run('DELETE FROM presentation_sessions WHERE id = ?', [id]);
  }

  async get(id: string): Promise<SessionRecord | undefined> {
    const row = this.db.get<SessionRow>('SELECT * FROM presentation_sessions WHERE id = ?', [id]);

    return row ? rowToRecord(row) : undefined;
  }

  async insert(id: string, requestObject?: string): Promise<void> {
    this.db.run(
      `INSERT INTO presentation_sessions (id, state, request_object, response, created_at)
       VALUES (?, 'pending', ?, NULL, ?)`,
      [id, requestObject ?? null, Date.now()]
    );
  }

  async update(id: string, state: SessionState, response?: string): Promise<void> {
    this.db.run(`UPDATE presentation_sessions SET state = ?, response = ? WHERE id = ?`, [state, response ?? null, id]);
  }
}
