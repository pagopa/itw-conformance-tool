import { homedir } from 'node:os';
import { resolve } from 'node:path';

import { DatabaseClient, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';

const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');
const rpDataDir = process.env.ITW_CT_DATA_DIR ?? DEFAULT_DATA_DIR;

const databaseClient = new DatabaseClient({ dataDir: rpDataDir });
const repository = new SqliteSessionRepository(databaseClient.db);

export const sessionService = new SessionService(repository);

export function closeSessionStorage(): void {
  databaseClient.close();
}
