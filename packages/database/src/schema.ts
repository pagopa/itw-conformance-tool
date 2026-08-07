export const DDL = `
  CREATE TABLE IF NOT EXISTS nonces (
    value      TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS relying_party_nonces (
    id         TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS relying_party_request_objects (
    id           TEXT    PRIMARY KEY,
    expires_at   INTEGER NOT NULL,
    flow_type    TEXT    NOT NULL CHECK(flow_type IN ('same-device', 'cross-device')),
    jwt          TEXT    NOT NULL,
    session_id   TEXT    NOT NULL UNIQUE,
    user_agent_session_id TEXT,
    redirect_uri TEXT,
    status       TEXT    NOT NULL CHECK(status IN ('checking', 'denied', 'expired', 'pending', 'rejected', 'verified')),
    values_json  TEXT CHECK(values_json IS NULL OR json_valid(values_json))
  );

  CREATE INDEX IF NOT EXISTS relying_party_request_objects_expires_at_idx
    ON relying_party_request_objects(expires_at);

  CREATE TABLE IF NOT EXISTS par_entries (
    request_uri    TEXT    PRIMARY KEY,
    client_id      TEXT    NOT NULL,
    request_object TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS deferred_credentials (
    id              TEXT NOT NULL PRIMARY KEY,
    subject         TEXT NOT NULL,
    jwk_thumbprint  TEXT NOT NULL,
    notification_id TEXT NOT NULL,
    credentials     TEXT NOT NULL CHECK(json_valid(credentials))
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti                         TEXT    PRIMARY KEY,
    client_id                   TEXT    NOT NULL,
    subject                     TEXT    NOT NULL,
    dpop_jkt                    TEXT    NOT NULL,
    authorization_details_json  TEXT    NOT NULL CHECK(json_valid(authorization_details_json)),
    scope                       TEXT,
    auth_flow                   TEXT,
    expires_at                  INTEGER NOT NULL,
    consumed_at                 INTEGER
  );

  CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx
    ON refresh_tokens(expires_at);

  CREATE TABLE IF NOT EXISTS presentation_sessions (
    id             TEXT    PRIMARY KEY,
    state          TEXT    NOT NULL CHECK(state IN ('pending', 'completed', 'failed')),
    request_object TEXT,
    response       TEXT,
    created_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conformance_sessions (
    id          TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    closed_at   TEXT,
    entity_name TEXT NOT NULL DEFAULT '-',
    phase       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'OPEN'
  );

  CREATE TABLE IF NOT EXISTS conformance_checks (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES conformance_sessions(id),
    requirement_id TEXT NOT NULL,
    description    TEXT NOT NULL,
    phase          TEXT NOT NULL,
    result         TEXT NOT NULL,
    timestamp      TEXT NOT NULL,
    error_message  TEXT
  );

  CREATE TABLE IF NOT EXISTS conformance_events (
    id             TEXT    PRIMARY KEY,
    name           TEXT    NOT NULL,
    correlation_id TEXT,
    service        TEXT    NOT NULL,
    timestamp      TEXT    NOT NULL,
    monotonic_ms   REAL    NOT NULL,
    request_id     TEXT,
    artifact_refs  TEXT,
    diagnostic     TEXT,
    http           TEXT,
    error          TEXT,
    validation     TEXT
  );

  CREATE INDEX IF NOT EXISTS conformance_events_timestamp_idx
    ON conformance_events(timestamp, id);
`;
