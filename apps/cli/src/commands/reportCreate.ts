import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { EmitLog } from '../types/types.js';
import type { ReportFormat } from '@itw-conformance-tool/conformance';

/** Generates a conformance report file for the given run ID.
 *
 * Saves the report as `conformance-report-<runId>.<format>` in the current
 * working directory. Throws if the session is not found, and lets the caller
 * decide the process exit code.
 *
 * @param runId - The UUID of the conformance session to report on.
 * @param format - Output format: 'html' or 'pdf'.
 * @param dataDir - Absolute path to the data directory containing the
 * SQLite database.
 * @returns void.
 */
export async function reportCreate(
  runId: string,
  format: ReportFormat,
  dataDir: string,
  emitter: EmitLog
): Promise<void> {
  const dbPath = join(dataDir, 'itw.db');
  const db = new DatabaseSync(dbPath, { open: true });

  try {
    const {
      SqliteConformanceSessionRepository,
      buildJsonReporterFromSession,
      generateRenderedReport
    } = await import('@itw-conformance-tool/conformance');

    const repository = new SqliteConformanceSessionRepository(db);
    const session = await repository.get(runId);

    if (!session) {
      throw new Error(`Conformance run '${runId}' not found in the database.`);
    }

    const jsonReporter = buildJsonReporterFromSession(session);
    const rendered = generateRenderedReport(format, jsonReporter, { generatedAt: new Date() });

    const fileName = `conformance-report-${runId}.${rendered.extension}`;
    const outputPath = resolve(process.cwd(), fileName);

    if (rendered.content instanceof Uint8Array) {
      writeFileSync(outputPath, rendered.content);
    } else {
      writeFileSync(outputPath, rendered.content, 'utf-8');
    }

    emitter(`Report saved at: ${outputPath}\n`, 'info');
  } finally {
    db.close();
  }
}
