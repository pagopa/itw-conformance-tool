import { writeFileSync } from 'node:fs';
import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import {
  getLatestSessionId,
  getSession,
  renderHtml,
  renderPdf,
  type ReportView
} from '@itw-conformance-tool/conformance';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { logger } from '@itw-conformance-tool/logger';

type ReportFormat = 'html' | 'pdf';

export async function reportCreate(runReference: string, format: string, view = 'both'): Promise<void> {
  assertReportFormat(format);
  assertReportView(view);

  const config = loadConfig();
  const db = new DatabaseClient(config.global.data_dir);

  try {
    const resolvedRunId = runReference === 'latest' ? getLatestSessionId(db) : runReference;

    if (!resolvedRunId) {
      logger.error('No conformance runs found.');
      process.exitCode = 1;
      return;
    }

    const session = getSession(db, resolvedRunId);
    if (!session) {
      logger.error(`Conformance run not found: ${runReference}`);
      process.exitCode = 1;
      return;
    }

    const html = renderHtml(session, config, view);
    const outputPath = path.resolve(process.cwd(), `conformance-report-${resolvedRunId}.${format}`);

    if (format === 'html') {
      writeFileSync(outputPath, html, 'utf8');
      logger.info(outputPath);
      return;
    }

    const pdf = await renderPdf(html);
    writeFileSync(outputPath, pdf);
    logger.info(outputPath);
  } finally {
    db.close();
  }
}

function assertReportFormat(format: string): asserts format is ReportFormat {
  if (format === 'html' || format === 'pdf') {
    return;
  }

  throw new Error(`Invalid report format: ${format}. Expected one of: html, pdf.`);
}

function assertReportView(view: string): asserts view is ReportView {
  if (view === 'both' || view === 'executive' || view === 'technical') {
    return;
  }

  throw new Error(`Invalid report view: ${view}. Expected one of: both, executive, technical.`);
}
