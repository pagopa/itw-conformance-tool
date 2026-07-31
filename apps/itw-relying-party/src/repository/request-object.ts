import type { DatabaseClient } from '@itw-conformance-tool/database';

type FlowType = 'same-device' | 'cross-device';
type RequestObjectStatus = 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';

export interface RequestObject {
  expiresAt: number;
  flowType: FlowType;
  id: string; // state
  jwt: string;
  sessionId: string;
  redirectUri?: string;
  status: RequestObjectStatus;
  values?: Record<string, null | string>[];
}

type RequestObjectRow = {
  expires_at: number;
  flow_type: FlowType;
  id: string;
  jwt: string;
  redirect_uri: string | null;
  session_id: string;
  status: RequestObjectStatus;
  values_json: string | null;
};

function toRequestObject(row: RequestObjectRow): RequestObject {
  return {
    expiresAt: row.expires_at,
    flowType: row.flow_type,
    id: row.id,
    jwt: row.jwt,
    sessionId: row.session_id,
    ...(row.redirect_uri ? { redirectUri: row.redirect_uri } : {}),
    status: row.status,
    ...(row.values_json ? { values: JSON.parse(row.values_json) as Record<string, null | string>[] } : {})
  };
}

export class RequestObjectRepository {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  public list(): RequestObject[] {
    return this.db.query<RequestObjectRow>('SELECT * FROM relying_party_request_objects').map(toRequestObject);
  }

  public delete(requestObjectId: string): void {
    const result = this.db.run('DELETE FROM relying_party_request_objects WHERE id = ?', [requestObjectId]);
    if (result.changes === 0) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }
  }

  public get(requestObjectId: string): RequestObject {
    const requestObject = this.db.get<RequestObjectRow>('SELECT * FROM relying_party_request_objects WHERE id = ?', [
      requestObjectId
    ]);
    if (!requestObject) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }

    return toRequestObject(requestObject);
  }

  public getBySessionId(sessionId: string): RequestObject {
    const requestObject = this.db.get<RequestObjectRow>(
      'SELECT * FROM relying_party_request_objects WHERE session_id = ?',
      [sessionId]
    );
    if (!requestObject) {
      throw new Error(`Request object with responseUriId ${sessionId} not found`);
    }

    return toRequestObject(requestObject);
  }

  public insert({
    flowType,
    sessionId,
    id,
    jwt
  }: {
    flowType: FlowType;
    sessionId: string;
    id: string;
    jwt: string;
  }): void {
    this.db.run(
      `INSERT INTO relying_party_request_objects (id, expires_at, flow_type, jwt, session_id, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [id, Date.now() + 5 * 60 * 1000, flowType, jwt, sessionId]
    );
  }

  public update(
    requestObjectId: string,
    status: Exclude<RequestObjectStatus, 'pending'>,
    redirectUri?: string,
    values?: Record<string, null | string>[]
  ): void {
    const result = this.db.run(
      `UPDATE relying_party_request_objects
       SET status = ?, redirect_uri = CASE WHEN ? = 'verified' AND ? IS NOT NULL THEN ? ELSE redirect_uri END,
           values_json = CASE WHEN ? IS NOT NULL THEN ? ELSE values_json END
       WHERE id = ?`,
      [
        status,
        status,
        redirectUri ?? null,
        redirectUri ?? null,
        values ? JSON.stringify(values) : null,
        values ? JSON.stringify(values) : null,
        requestObjectId
      ]
    );
    if (result.changes === 0) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }
  }
}
