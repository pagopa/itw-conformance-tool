import { DatabaseClient } from '@itw-conformance-tool/database';

import type { EmitLog } from '../types/types.js';

type SessionRow = {
  session_id: string;
  started_at: string;
  closed_at: string | null;
  status: string;
  checks: string;
};

function calcPad(value: string, width: number): string {
  return value.padEnd(width + 2);
}

/**
 * Prints a formatted table of all conformance sessions to stdout.
 */
export function reportList(dataDir: string, emitter: EmitLog): void {
  const db = new DatabaseClient(dataDir);

  try {
    const rows = db.query<SessionRow>(`
      SELECT
        session_id,
        started_at,
        closed_at,
        status,
        checks
      FROM conformance_sessions
      ORDER BY started_at DESC
    `);

    if (rows.length === 0) {
      emitter('No conformance runs found in the database.\n', 'info');
      return;
    }

    const columns = {
      runId: 'RUN ID',
      startedAt: 'STARTED AT',
      closedAt: 'CLOSED AT',
      status: 'STATUS',
      checks: 'CHECKS'
    };

    const data = rows.map((row) => ({
      runId: row.session_id,
      startedAt: row.started_at,
      closedAt: row.closed_at ?? '-',
      status: row.status,
      checks: String((JSON.parse(row.checks) as unknown[]).length)
    }));

    const widths = {
      runId: Math.max(columns.runId.length, ...data.map((r) => r.runId.length)),
      startedAt: Math.max(columns.startedAt.length, ...data.map((r) => r.startedAt.length)),
      closedAt: Math.max(columns.closedAt.length, ...data.map((r) => r.closedAt.length)),
      status: Math.max(columns.status.length, ...data.map((r) => r.status.length)),
      checks: Math.max(columns.checks.length, ...data.map((r) => r.checks.length))
    };

    // Print header
    process.stdout.write(
      `${calcPad(columns.runId, widths.runId)}${calcPad(columns.startedAt, widths.startedAt)}${calcPad(columns.closedAt, widths.closedAt)}${calcPad(columns.status, widths.status)}${calcPad(columns.checks, widths.checks)}\n`
    );

    // Print data rows
    for (const row of data) {
      process.stdout.write(
        `${calcPad(row.runId, widths.runId)}${calcPad(row.startedAt, widths.startedAt)}${calcPad(row.closedAt, widths.closedAt)}${calcPad(row.status, widths.status)}${calcPad(row.checks, widths.checks)}\n`
      );
    }
  } finally {
    db.close();
  }
}
