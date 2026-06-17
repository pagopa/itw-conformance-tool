import { describe, it, expect, vi, beforeEach } from 'vitest';

import { reportList } from '../../commands/reportList.js';

import type { EmitLog } from '../../types/types.js';

// ── Database mock ─────────────────────────────────────────────────────────────
// Shared state lets tests configure rows and observe close calls across the
// class constructor boundary without capturing top-level variables (hoisting).

const dbState = {
  rows: [] as unknown[],
  closed: false
};

vi.mock('node:sqlite', () => {
  return {
    DatabaseSync: vi.fn(function (this: Record<string, unknown>) {
      this.prepare = (_sql: string) => ({ all: () => dbState.rows });
      this.close = () => { dbState.closed = true; };
    })
  };
});

// ── Constants ─────────────────────────────────────────────────────────────────

const emitLog: EmitLog = vi.fn();
const DATA_DIR = '/data';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('reportList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    dbState.rows = [];
    dbState.closed = false;
  });

  it('emits an info message when no sessions are found', () => {
    reportList(DATA_DIR, emitLog);

    expect(emitLog).toHaveBeenCalledWith('No conformance runs found in the database.\n', 'info');
  });

  it('closes the database even when no sessions are found', () => {
    reportList(DATA_DIR, emitLog);

    expect(dbState.closed).toBe(true);
  });

  it('opens the database at the correct path', async () => {
    const { DatabaseSync } = await import('node:sqlite');

    reportList(DATA_DIR, emitLog);

    expect(DatabaseSync).toHaveBeenCalledWith('/data/itw.db', { open: true });
  });

  it('prints header and rows when sessions are present', () => {
    dbState.rows = [
      {
        session_id: 'aaaaaaaa-0000-0000-0000-000000000001',
        started_at: '2024-01-01T10:00:00.000Z',
        closed_at: '2024-01-01T10:05:00.000Z',
        status: 'closed',
        checks: JSON.stringify([{}, {}])
      },
      {
        session_id: 'aaaaaaaa-0000-0000-0000-000000000002',
        started_at: '2024-01-02T11:00:00.000Z',
        closed_at: null,
        status: 'open',
        checks: JSON.stringify([{}])
      }
    ];

    const written: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((s) => {
      written.push(String(s));
      return true;
    });

    reportList(DATA_DIR, emitLog);

    // Header line must include all column names
    expect(written[0]).toContain('RUN ID');
    expect(written[0]).toContain('STARTED AT');
    expect(written[0]).toContain('CLOSED AT');
    expect(written[0]).toContain('STATUS');
    expect(written[0]).toContain('CHECKS');

    // First data row
    expect(written[1]).toContain('aaaaaaaa-0000-0000-0000-000000000001');
    expect(written[1]).toContain('closed');
    expect(written[1]).toContain('2');

    // Second row: null closed_at must be rendered as '-'
    expect(written[2]).toContain('aaaaaaaa-0000-0000-0000-000000000002');
    expect(written[2]).toContain('-');
    expect(written[2]).toContain('open');
  });

  it('closes the database even when sessions are present', () => {
    dbState.rows = [
      {
        session_id: 'aaaaaaaa-0000-0000-0000-000000000001',
        started_at: '2024-01-01T10:00:00.000Z',
        closed_at: null,
        status: 'open',
        checks: '[]'
      }
    ];

    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    reportList(DATA_DIR, emitLog);

    expect(dbState.closed).toBe(true);
  });
});
