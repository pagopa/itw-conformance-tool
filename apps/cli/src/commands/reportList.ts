import { loadConfig } from '@itw-conformance-tool/config';
import { listSessions } from '@itw-conformance-tool/conformance';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { logger } from '@itw-conformance-tool/logger';

const RUN_ID_WIDTH = 36;
const STARTED_AT_WIDTH = 24;
const CLOSED_AT_WIDTH = 24;
const STATUS_WIDTH = 10;

export function reportList(): void {
  const config = loadConfig();
  const db = new DatabaseClient(config.global.data_dir);

  try {
    const sessions = listSessions(db);
    if (sessions.length === 0) {
      logger.warn('No conformance runs found.');
      return;
    }

    const header = [
      'RUN ID'.padEnd(RUN_ID_WIDTH),
      'STARTED AT'.padEnd(STARTED_AT_WIDTH),
      'CLOSED AT'.padEnd(CLOSED_AT_WIDTH),
      'STATUS'.padEnd(STATUS_WIDTH),
      'CHECKS'
    ].join(' ');

    const rows = sessions.map((session) =>
      [
        session.runId.padEnd(RUN_ID_WIDTH),
        session.startedAt.padEnd(STARTED_AT_WIDTH),
        (session.closedAt ?? '-').padEnd(CLOSED_AT_WIDTH),
        session.status.padEnd(STATUS_WIDTH),
        String(session.checksPerformed)
      ].join(' ')
    );

    logger.info(header);
    for (const row of rows) {
      logger.info(row);
    }
  } finally {
    db.close();
  }
}
