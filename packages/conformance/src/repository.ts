import type {
  ClosedConformanceSessionStatus,
  ConformanceCheck,
  ConformanceSession,
  ConformanceSessionStatus,
  IConformanceSessionRepository
} from './models/types.js';
import type { DatabaseClient } from '@itw-conformance-tool/database';

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
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async create(session: ConformanceSession): Promise<void> {
    this.db.run(
      `INSERT INTO conformance_sessions (session_id, started_at, closed_at, status, checks)
       VALUES (?, ?, ?, ?, ?)`,
      [session.sessionId, session.startedAt, session.closedAt ?? null, session.status, JSON.stringify(session.checks)]
    );
  }

  async get(sessionId: string): Promise<ConformanceSession | null> {
    const row = this.db.get<SessionRow>('SELECT * FROM conformance_sessions WHERE session_id = ?', [sessionId]);

    return row ? rowToSession(row) : null;
  }

  async appendCheck(sessionId: string, check: ConformanceCheck): Promise<void> {
    // Atomic append avoids read-modify-write races when multiple test results
    // are persisted close together.
    this.db.run(
      `UPDATE conformance_sessions
       SET checks = json_insert(checks, '$[#]', json(?))
       WHERE session_id = ? AND status = 'OPEN'`,
      [JSON.stringify(check), sessionId]
    );
  }

  async close(sessionId: string, status: ClosedConformanceSessionStatus): Promise<void> {
    this.db.run(
      `UPDATE conformance_sessions
       SET status = ?, closed_at = ?
       WHERE session_id = ? AND status = 'OPEN'`,
      [status, new Date().toISOString(), sessionId]
    );
  }

  async markOpenSessionsIncompleteOlderThan(cutoffIso: string): Promise<number> {
    const result = this.db.run(
      `UPDATE conformance_sessions
       SET status = 'INCOMPLETE', closed_at = ?
       WHERE status = 'OPEN'
         AND started_at < ?`,
      [new Date().toISOString(), cutoffIso]
    );

    return Number(result.changes);
  }
}
