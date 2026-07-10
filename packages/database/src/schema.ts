export const DDL = `
  CREATE TABLE IF NOT EXISTS nonces (
    value      TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS par_entries (
    request_uri    TEXT    PRIMARY KEY,
    client_id      TEXT    NOT NULL,
    request_object TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS presentation_sessions (
    id             TEXT    PRIMARY KEY,
    state          TEXT    NOT NULL CHECK(state IN ('pending', 'completed', 'failed')),
    request_object TEXT,
    response       TEXT,
    created_at     INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conformance_sessions (
    session_id  TEXT    PRIMARY KEY,
    started_at  TEXT    NOT NULL,
    closed_at   TEXT,
    status      TEXT    NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'PASSED', 'FAILED', 'INCOMPLETE')),
    checks      TEXT    NOT NULL DEFAULT '[]' CHECK(json_type(checks) = 'array')
  );

  CREATE TABLE IF NOT EXISTS conformance_events (
    id             TEXT    PRIMARY KEY,
    name           TEXT    NOT NULL,
    scenario_id    TEXT,
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
