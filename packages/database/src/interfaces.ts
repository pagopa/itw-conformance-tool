// ---------------------------------------------------------------------------
// Repository interfaces exposed by @itw-conformance-tool/database.
// Domain packages (issuer, rp) depend on these interfaces — not on the
// concrete SQLite implementations — so they stay testable in isolation.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

export interface INonceRepository {
  /** Atomically consumes a nonce if present and not expired. */
  consume(value: string): Promise<boolean>;
  /** Removes a nonce so it cannot be used again. No-op if not found. */
  delete(value: string): Promise<void>;
  /** Returns the nonce string, or undefined if it does not exist or has expired. */
  get(value: string): Promise<string | undefined>;
  /** Persists a nonce with the given expiry timestamp (ms since epoch). */
  insert(value: string, expiresAtMs: number): Promise<void>;
}

// ---------------------------------------------------------------------------
// PAR (Pushed Authorization Request)
// ---------------------------------------------------------------------------

export interface PAREntry {
  /** Absolute request_uri used as primary key. */
  requestUri: string;
  clientId: string;
  /** Full PAR object serialised as JSON. */
  requestObject: string;
  /** Expiry of the PAR entry itself (ms since epoch). */
  expiresAt: number;
}

export interface IPARRepository {
  delete(requestUri: string): Promise<void>;
  get(requestUri: string): Promise<PAREntry | undefined>;
  insert(entry: PAREntry): Promise<void>;
  /** Partially updates an existing PAR entry. */
  update(requestUri: string, data: Partial<Omit<PAREntry, 'requestUri'>>): Promise<void>;
}

// ---------------------------------------------------------------------------
// Presentation session (Relying Party)
// ---------------------------------------------------------------------------

export type SessionState = 'pending' | 'completed' | 'failed';

export interface SessionRecord {
  id: string;
  state: SessionState;
  /** JWT request object. */
  requestObject: string | null;
  /** JSON-serialised response payload. */
  response: string | null;
  /** Creation timestamp (ms since epoch). */
  createdAt: number;
}

export interface ISessionRepository {
  delete(id: string): Promise<void>;
  /** Returns the session record, or undefined if not found. */
  get(id: string): Promise<SessionRecord | undefined>;
  insert(id: string, requestObject?: string): Promise<void>;
  update(id: string, state: SessionState, response?: string): Promise<void>;
}
