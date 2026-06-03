import type {
  ConformanceCheck,
  ConformanceSession,
  ConformanceSessionStatus,
  IConformanceSessionRepository
} from '@itw-conformance-tool/database';
import type { DatabaseSync } from 'node:sqlite';

type SessionRow = {
  session_id: string;
  started_at: string;
  closed_at: string | null;
  status: string;
  checks: string;
};

function rowToSession(row: SessionRow): ConformanceSession {
  return {
    sessionId: row.session_id,
    startedAt: row.started_at,
    closedAt: row.closed_at ?? undefined,
    status: row.status as ConformanceSessionStatus,
    checks: JSON.parse(row.checks) as ConformanceCheck[]
  };
}

export class SqliteConformanceSessionRepository implements IConformanceSessionRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async create(session: ConformanceSession): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO conformance_sessions (session_id, started_at, closed_at, status, checks)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(
        session.sessionId,
        session.startedAt,
        session.closedAt ?? null,
        session.status,
        JSON.stringify(session.checks)
      );
  }

  async get(sessionId: string): Promise<ConformanceSession | null> {
    const row = this.db.prepare('SELECT * FROM conformance_sessions WHERE session_id = ?').get(sessionId) as
      | SessionRow
      | undefined;

    return row ? rowToSession(row) : null;
  }

  async appendCheck(sessionId: string, check: ConformanceCheck): Promise<void> {
    const row = this.db.prepare('SELECT checks FROM conformance_sessions WHERE session_id = ?').get(sessionId) as
      | { checks: string }
      | undefined;

    if (!row) return;

    const checks = JSON.parse(row.checks) as ConformanceCheck[];
    checks.push(check);

    this.db
      .prepare('UPDATE conformance_sessions SET checks = ? WHERE session_id = ?')
      .run(JSON.stringify(checks), sessionId);
  }

  async close(sessionId: string, status: 'PASSED' | 'FAILED' | 'INCOMPLETE'): Promise<void> {
    this.db
      .prepare(
        `UPDATE conformance_sessions
         SET status = ?, closed_at = ?
         WHERE session_id = ?`
      )
      .run(status, new Date().toISOString(), sessionId);
  }
}
