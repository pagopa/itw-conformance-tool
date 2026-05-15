import { homedir } from 'node:os';
import { resolve } from 'node:path';

import { DatabaseClient } from '@itw-conformance-tool/database';

import type { DatabaseSync } from 'node:sqlite';

export interface RequestObject {
  expiresAt: number;
  flowType: 'cross-device' | 'same-device';
  id: string;
  jwt: string;
  redirectUri?: string;
  status: 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';
  values?: Record<string, null | string>[];
}

export interface RequestObjectRepository {
  delete: (id: RequestObject['id']) => Promise<void>;
  get: (id: RequestObject['id']) => Promise<RequestObject>;
  insert: (requestObject: Pick<RequestObject, 'flowType' | 'id' | 'jwt'>) => Promise<void>;
  update: (
    id: RequestObject['id'],
    status: 'checking' | 'denied' | 'expired' | 'rejected' | 'verified',
    redirectUri?: string,
    values?: Record<string, null | string>[]
  ) => Promise<void>;
}

type RequestObjectRow = {
  expires_at: number;
  flow_type: 'cross-device' | 'same-device';
  id: string;
  jwt: string;
  redirect_uri: null | string;
  status: 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';
  values_json: null | string;
};

const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');
const rpDataDir = process.env.ITW_CT_DATA_DIR ?? DEFAULT_DATA_DIR;
const databaseClient = new DatabaseClient({ dataDir: rpDataDir });
const database = databaseClient.db;

database.exec(`
  CREATE TABLE IF NOT EXISTS rp_request_objects (
    id          TEXT PRIMARY KEY,
    flow_type   TEXT NOT NULL CHECK(flow_type IN ('same-device', 'cross-device')),
    jwt         TEXT NOT NULL,
    status      TEXT NOT NULL CHECK(status IN ('pending', 'checking', 'verified', 'rejected', 'denied', 'expired')),
    redirect_uri TEXT,
    values_json TEXT,
    expires_at  INTEGER NOT NULL
  );
`);

function rowToRequestObject(row: RequestObjectRow): RequestObject {
  return {
    expiresAt: row.expires_at,
    flowType: row.flow_type,
    id: row.id,
    jwt: row.jwt,
    redirectUri: row.redirect_uri ?? undefined,
    status: row.status,
    values: row.values_json !== null ? (JSON.parse(row.values_json) as Record<string, null | string>[]) : undefined
  };
}

function purgeExpiredRows(db: DatabaseSync): void {
  db.prepare(
    `UPDATE rp_request_objects
     SET status = 'expired'
     WHERE expires_at < unixepoch('now') * 1000
       AND status IN ('pending', 'checking')`
  ).run();
}

export async function markAsExpired(): Promise<void> {
  purgeExpiredRows(database);
}

export function closeRequestObjectStorage(): void {
  databaseClient.close();
}

export const requestObjectRepository: RequestObjectRepository = {
  async delete(id) {
    database.prepare(`DELETE FROM rp_request_objects WHERE id = ?`).run(id);
  },
  async get(id) {
    purgeExpiredRows(database);
    const row = database
      .prepare(
        `SELECT id, flow_type, jwt, status, redirect_uri, values_json, expires_at
         FROM rp_request_objects
         WHERE id = ?`
      )
      .get(id) as RequestObjectRow | undefined;

    if (row === undefined) {
      throw new Error('Request object not found');
    }

    return rowToRequestObject(row);
  },
  async insert({ flowType, id, jwt }) {
    database
      .prepare(
        `INSERT INTO rp_request_objects (id, flow_type, jwt, status, redirect_uri, values_json, expires_at)
         VALUES (?, ?, ?, 'pending', NULL, NULL, ?)`
      )
      .run(id, flowType, jwt, Date.now() + 5 * 60 * 1000);
  },
  async update(id, status, redirectUri, values) {
    database
      .prepare(
        `UPDATE rp_request_objects
         SET status = ?, redirect_uri = ?, values_json = COALESCE(?, values_json)
         WHERE id = ?`
      )
      .run(status, redirectUri ?? null, values !== undefined ? JSON.stringify(values) : null, id);
  }
};
