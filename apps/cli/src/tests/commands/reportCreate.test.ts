import { describe, it, expect, vi, beforeEach } from 'vitest';

import { reportCreate } from '../../commands/reportCreate.js';

import type { EmitLog } from '../../types/types.js';

// ── Database mock ─────────────────────────────────────────────────────────────
// Shared state lets tests observe close calls without capturing top-level vars.

const dbState = {
  closed: false
};

vi.mock('node:sqlite', () => {
  return {
    DatabaseSync: vi.fn(function (this: Record<string, unknown>) {
      this.close = () => {
        dbState.closed = true;
      };
    })
  };
});

// ── Conformance package mock ──────────────────────────────────────────────────

vi.mock('@itw-conformance-tool/conformance', () => ({
  SqliteConformanceSessionRepository: vi.fn(),
  buildJsonReporterFromSession: vi.fn(() => ({ reporter: 'json' })),
  generateRenderedReport: vi.fn()
}));

vi.mock('node:fs', () => ({
  writeFileSync: vi.fn()
}));

// ── Constants ─────────────────────────────────────────────────────────────────

const emitLog: EmitLog = vi.fn();
const DATA_DIR = '/data';
const RUN_ID = 'aaaaaaaa-0000-0000-0000-000000000001';

describe('reportCreate', () => {
  let mockGet: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    dbState.closed = false;

    mockGet = vi.fn();

    const { SqliteConformanceSessionRepository } = await import('@itw-conformance-tool/conformance');
    vi.mocked(SqliteConformanceSessionRepository).mockImplementation(
      vi.fn(function (this: Record<string, unknown>) {
        this.get = mockGet;
      }) as never
    );
  });

  it('throws when the session is not found', async () => {
    mockGet.mockResolvedValue(null);

    await expect(reportCreate(RUN_ID, 'html', DATA_DIR, emitLog)).rejects.toThrow(
      `Conformance run '${RUN_ID}' not found in the database.`
    );
  });

  it('closes the database even when the session is not found', async () => {
    mockGet.mockResolvedValue(null);

    await expect(reportCreate(RUN_ID, 'html', DATA_DIR, emitLog)).rejects.toThrow();

    expect(dbState.closed).toBe(true);
  });

  it('writes an html file and emits the output path', async () => {
    const { writeFileSync } = await import('node:fs');
    const { generateRenderedReport } = await import('@itw-conformance-tool/conformance');
    mockGet.mockResolvedValue({ id: RUN_ID });
    vi.mocked(generateRenderedReport).mockReturnValue({ extension: 'html', content: '<html/>' } as never);

    await reportCreate(RUN_ID, 'html', DATA_DIR, emitLog);

    expect(writeFileSync).toHaveBeenCalledOnce();
    const [writtenPath, writtenContent, writtenOpts] = vi.mocked(writeFileSync).mock.calls[0];
    expect(writtenPath).toContain(`conformance-report-${RUN_ID}.html`);
    expect(writtenContent).toBe('<html/>');
    expect(writtenOpts).toBe('utf-8');
    expect(emitLog).toHaveBeenCalledWith(expect.stringContaining(`conformance-report-${RUN_ID}.html`), 'info');
  });

  it('writes a pdf file as binary (Uint8Array) without encoding option', async () => {
    const { writeFileSync } = await import('node:fs');
    const { generateRenderedReport } = await import('@itw-conformance-tool/conformance');
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    mockGet.mockResolvedValue({ id: RUN_ID });
    vi.mocked(generateRenderedReport).mockReturnValue({ extension: 'pdf', content: pdfBytes } as never);

    await reportCreate(RUN_ID, 'pdf', DATA_DIR, emitLog);

    expect(writeFileSync).toHaveBeenCalledOnce();
    const [writtenPath, writtenContent, writtenOpts] = vi.mocked(writeFileSync).mock.calls[0];
    expect(writtenPath).toContain(`conformance-report-${RUN_ID}.pdf`);
    expect(writtenContent).toBeInstanceOf(Uint8Array);
    expect(writtenOpts).toBeUndefined();
  });

  it('opens the database at the correct path', async () => {
    const { DatabaseSync } = await import('node:sqlite');
    mockGet.mockResolvedValue(null);

    await expect(reportCreate(RUN_ID, 'html', DATA_DIR, emitLog)).rejects.toThrow();

    expect(DatabaseSync).toHaveBeenCalledWith('/data/itw.db', { open: true });
  });

  it('passes the correct format to generateRenderedReport', async () => {
    const { generateRenderedReport } = await import('@itw-conformance-tool/conformance');
    mockGet.mockResolvedValue({ id: RUN_ID });
    vi.mocked(generateRenderedReport).mockReturnValue({ extension: 'pdf', content: new Uint8Array() } as never);

    await reportCreate(RUN_ID, 'pdf', DATA_DIR, emitLog);

    expect(generateRenderedReport).toHaveBeenCalledWith('pdf', expect.anything(), expect.anything());
  });

  it('closes the database on success', async () => {
    const { generateRenderedReport } = await import('@itw-conformance-tool/conformance');
    mockGet.mockResolvedValue({ id: RUN_ID });
    vi.mocked(generateRenderedReport).mockReturnValue({ extension: 'html', content: '<html/>' } as never);

    await reportCreate(RUN_ID, 'html', DATA_DIR, emitLog);

    expect(dbState.closed).toBe(true);
  });
});
