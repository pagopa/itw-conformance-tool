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
  getByJti(jti: string): Promise<PAREntry | undefined>;
  getByMrtdAuthSession(sessionId: string): Promise<PAREntry | undefined>;
  insert(entry: PAREntry): Promise<void>;
  /** Partially updates an existing PAR entry. */
  update(requestUri: string, data: Partial<Omit<PAREntry, 'requestUri'>>): Promise<void>;
}

// ---------------------------------------------------------------------------
// Deferred credentials (Credential Issuer)
// ---------------------------------------------------------------------------

export interface DeferredCredentialEntry {
  /** Serialised credentials generated for the original batch request. */
  credentials: string[];
  /** Subject (`sub`) of the access token that authorized the original request. */
  subject: string;
  /** JWK thumbprint (`cnf.jkt`) bound to the access token. */
  jwkThumbprint: string;
  /** Notification ID to return alongside the deferred credentials. */
  notificationId: string;
}

export interface IDeferredCredentialRepository {
  /**
   * Atomically retrieves and deletes the record matching `transactionId`, `subject`, and
   * `jwkThumbprint`. Returns `undefined` for unknown, mismatched, or already-consumed transactions.
   * Throws if the stored payload is not valid JSON matching {@link DeferredCredentialEntry}.
   */
  consume(transactionId: string, subject: string, jwkThumbprint: string): Promise<DeferredCredentialEntry | undefined>;
  /** Persists a new deferred credential batch under a cryptographically random `transactionId`. */
  insert(transactionId: string, record: DeferredCredentialEntry): Promise<void>;
}

// ---------------------------------------------------------------------------
// Refresh token (Credential Issuer)
// ---------------------------------------------------------------------------

export interface RefreshTokenEntry {
  /** JWT `jti` claim of the refresh token; primary key. */
  jti: string;
  clientId: string;
  /** Subject (`sub`) the refresh token was issued for. */
  subject: string;
  /** DPoP JWK thumbprint (`cnf.jkt`) the refresh token is bound to. */
  dpopJkt: string;
  /** Authorization details granted to the original access token. */
  authorizationDetails: unknown;
  /** Original scope, if any, so it can be re-asserted (or narrowed) on refresh. */
  scope?: string;
  /** Original `auth_flow` marker, if any. */
  authFlow?: string;
  /** Expiry of the refresh token itself (ms since epoch). */
  expiresAt: number;
  /** Timestamp the token was consumed (ms since epoch), or undefined while still valid. */
  consumedAt?: number;
}

export interface IRefreshTokenRepository {
  /** Persists a newly issued refresh token entry. */
  insert(entry: RefreshTokenEntry): Promise<void>;
  /**
   * Atomically consumes `oldJti` and inserts `newEntry` in its place.
   * Returns the previous entry's authorization context on success, or
   * `undefined` if `oldJti` is unknown, expired, or already consumed —
   * guaranteeing that only one concurrent caller can rotate a given `jti`.
   */
  rotate(oldJti: string, newEntry: RefreshTokenEntry): Promise<RefreshTokenEntry | undefined>;
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
