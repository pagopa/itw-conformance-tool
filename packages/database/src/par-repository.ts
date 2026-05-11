import type { IPARRepository, PAREntry } from './interfaces.js';
import type { DatabaseSync } from 'node:sqlite';

type PARRow = {
  request_uri: string;
  client_id: string;
  request_object: string;
  expires_at: number;
};

function rowToEntry(row: PARRow): PAREntry {
  return {
    requestUri: row.request_uri,
    clientId: row.client_id,
    requestObject: row.request_object,
    expiresAt: row.expires_at
  };
}

export class SqlitePARRepository implements IPARRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  async delete(requestUri: string): Promise<void> {
    this.db.prepare('DELETE FROM par_entries WHERE request_uri = ?').run(requestUri);
  }

  async get(requestUri: string): Promise<PAREntry | undefined> {
    // Lazy expiry
    this.db.exec('DELETE FROM par_entries WHERE expires_at < unixepoch(\'now\') * 1000');

    const row = this.db
      .prepare('SELECT * FROM par_entries WHERE request_uri = ?')
      .get(requestUri) as PARRow | undefined;

    return row ? rowToEntry(row) : undefined;
  }

  async insert(entry: PAREntry): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO par_entries (request_uri, client_id, request_object, expires_at)
         VALUES (?, ?, ?, ?)`
      )
      .run(entry.requestUri, entry.clientId, entry.requestObject, entry.expiresAt);
  }

  async update(requestUri: string, data: Partial<Omit<PAREntry, 'requestUri'>>): Promise<void> {
    const fields: string[] = [];
    const values: (string | number | null)[] = [];

    if (data.clientId !== undefined) { fields.push('client_id = ?'); values.push(data.clientId); }
    if (data.requestObject !== undefined) { fields.push('request_object = ?'); values.push(data.requestObject); }
    if (data.expiresAt !== undefined) { fields.push('expires_at = ?'); values.push(data.expiresAt); }

    if (fields.length === 0) return;

    values.push(requestUri);
    this.db.prepare(`UPDATE par_entries SET ${fields.join(', ')} WHERE request_uri = ?`).run(...values);
  }
}
