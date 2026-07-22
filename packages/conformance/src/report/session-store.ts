import { randomUUID } from 'node:crypto';

import type { ConformanceCheck, ConformanceSession, Phase } from './types.js';
import type { DatabaseClient } from '@itw-conformance-tool/database';

export interface SessionSummary {
  checksPerformed: number;
  closedAt?: string;
  runId: string;
  startedAt: string;
  status: 'FAILED' | 'INCOMPLETE' | 'OPEN' | 'PASSED';
}

interface CheckRow {
  description: string;
  error_message: null | string;
  phase: ConformanceCheck['phase'];
  requirement_id: string;
  result: ConformanceCheck['result'];
  timestamp: string;
}

interface SessionRow {
  closed_at: null | string;
  entity_name: null | string;
  id: string;
  phase: Phase;
  started_at: string;
  status: 'FAILED' | 'INCOMPLETE' | 'OPEN' | 'PASSED';
}

export function appendCheck(db: DatabaseClient, sessionId: string, check: ConformanceCheck): void {
  db.run(
    `
      INSERT INTO conformance_checks (
        id,
        session_id,
        requirement_id,
        description,
        phase,
        result,
        timestamp,
        error_message
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      randomUUID(),
      sessionId,
      check.requirementId,
      check.description,
      check.phase,
      check.result,
      check.timestamp,
      check.errorMessage ?? null
    ]
  );
}

export function closeSession(
  db: DatabaseClient,
  sessionId: string,
  status: 'FAILED' | 'INCOMPLETE' | 'PASSED',
  closedAt: string
): void {
  db.run(
    `
      UPDATE conformance_sessions
      SET status = ?, closed_at = ?
      WHERE id = ?
    `,
    [status, closedAt, sessionId]
  );
}

export function createSession(db: DatabaseClient, session: Omit<ConformanceSession, 'checks'>): void {
  db.run(
    `
      INSERT INTO conformance_sessions (
        id,
        started_at,
        closed_at,
        entity_name,
        phase,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    [session.id, session.startedAt, session.closedAt ?? null, session.entityName, session.phase, session.status]
  );
}

export function getLatestOpenSessionId(db: DatabaseClient, phase: Phase): string | undefined {
  const row = db.get<{ id: string }>(
    `
      SELECT id
      FROM conformance_sessions
      WHERE phase = ? AND status = 'OPEN'
      ORDER BY started_at DESC, id DESC
      LIMIT 1
    `,
    [phase]
  );

  return row?.id;
}

export function getLatestSessionId(db: DatabaseClient): string | undefined {
  const row = db.get<{ id: string }>(`
    SELECT id
    FROM conformance_sessions
    ORDER BY started_at DESC, id DESC
    LIMIT 1
  `);

  return row?.id;
}

export function getSession(db: DatabaseClient, sessionId: string): ConformanceSession | undefined {
  const sessionRow = db.get<SessionRow>(
    `
      SELECT id, started_at, closed_at, entity_name, phase, status
      FROM conformance_sessions
      WHERE id = ?
    `,
    [sessionId]
  );

  if (!sessionRow) {
    return undefined;
  }

  const checksRows = db.query<CheckRow>(
    `
      SELECT
        requirement_id,
        description,
        phase,
        result,
        timestamp,
        error_message
      FROM conformance_checks
      WHERE session_id = ?
      ORDER BY timestamp ASC
    `,
    [sessionId]
  );

  return {
    checks: checksRows.map((check) => ({
      description: check.description,
      errorMessage: check.error_message ?? undefined,
      phase: check.phase,
      requirementId: check.requirement_id,
      result: check.result,
      timestamp: check.timestamp
    })),
    closedAt: sessionRow.closed_at ?? undefined,
    entityName: sessionRow.entity_name ?? '-',
    id: sessionRow.id,
    phase: sessionRow.phase,
    startedAt: sessionRow.started_at,
    status: sessionRow.status
  };
}

export function listSessions(db: DatabaseClient): SessionSummary[] {
  const rows = db.query<{
    checks_performed: number;
    closed_at: null | string;
    id: string;
    started_at: string;
    status: 'FAILED' | 'INCOMPLETE' | 'OPEN' | 'PASSED';
  }>(`
    SELECT
      s.id,
      s.started_at,
      s.closed_at,
      s.status,
      COUNT(c.id) AS checks_performed
    FROM conformance_sessions s
    LEFT JOIN checks c ON c.session_id = s.id
    GROUP BY s.id, s.started_at, s.closed_at, s.status
    ORDER BY s.started_at DESC
  `);

  return rows.map((row) => ({
    checksPerformed: row.checks_performed,
    closedAt: row.closed_at ?? undefined,
    runId: row.id,
    startedAt: row.started_at,
    status: row.status
  }));
}

export function updateSessionEntityName(db: DatabaseClient, sessionId: string, entityName: string): void {
  db.run(
    `
      UPDATE conformance_sessions
      SET entity_name = ?
      WHERE id = ?
    `,
    [entityName, sessionId]
  );
}
