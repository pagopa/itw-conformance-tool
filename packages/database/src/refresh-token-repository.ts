import type { DatabaseClient } from './client.js';
import type { IRefreshTokenRepository, RefreshTokenEntry } from './interfaces.js';

type RefreshTokenRow = {
  jti: string;
  client_id: string;
  subject: string;
  dpop_jkt: string;
  authorization_details_json: string;
  scope: string | null;
  auth_flow: string | null;
  expires_at: number;
  consumed_at: number | null;
};

function rowToEntry(row: RefreshTokenRow): RefreshTokenEntry {
  return {
    jti: row.jti,
    clientId: row.client_id,
    subject: row.subject,
    dpopJkt: row.dpop_jkt,
    authorizationDetails: JSON.parse(row.authorization_details_json),
    scope: row.scope ?? undefined,
    authFlow: row.auth_flow ?? undefined,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at ?? undefined
  };
}

export class SqliteRefreshTokenRepository implements IRefreshTokenRepository {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async insert(entry: RefreshTokenEntry): Promise<void> {
    this.insertRow(entry);
    this.deleteExpired(entry.jti);
  }

  async rotate(oldJti: string, newEntry: RefreshTokenEntry): Promise<RefreshTokenEntry | undefined> {
    return this.db.transaction(() => {
      const nowMs = Date.now();

      // Single atomic statement: the row is only marked consumed (and
      // returned) when it exists, is not expired, and has not already been
      // consumed. This prevents two concurrent requests from both rotating
      // the same `jti` — only one UPDATE can match and return a row.
      const consumedRow = this.db.get<RefreshTokenRow>(
        `UPDATE refresh_tokens
         SET consumed_at = ?
         WHERE jti = ?
           AND expires_at >= ?
           AND consumed_at IS NULL
         RETURNING *`,
        [nowMs, oldJti, nowMs]
      );

      if (!consumedRow) {
        return undefined;
      }

      this.insertRow(newEntry);
      this.deleteExpired(newEntry.jti);

      return rowToEntry(consumedRow);
    });
  }

  /** Inserts a new refresh token row. */
  private insertRow(entry: RefreshTokenEntry): void {
    this.db.run(
      `INSERT INTO refresh_tokens
         (jti, client_id, subject, dpop_jkt, authorization_details_json, scope, auth_flow, expires_at, consumed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      [
        entry.jti,
        entry.clientId,
        entry.subject,
        entry.dpopJkt,
        JSON.stringify(entry.authorizationDetails),
        entry.scope ?? null,
        entry.authFlow ?? null,
        entry.expiresAt
      ]
    );
  }

  /**
   * Opportunistically removes expired records so the table does not grow
   * unbounded, avoiding the need for a separate scheduled cleanup job.
   * `keepJti` is excluded so the row just inserted is never removed even if
   * clock skew makes `expires_at` look stale.
   */
  private deleteExpired(keepJti: string): void {
    this.db.run('DELETE FROM refresh_tokens WHERE expires_at < ? AND jti != ?', [Date.now(), keepJti]);
  }
}
