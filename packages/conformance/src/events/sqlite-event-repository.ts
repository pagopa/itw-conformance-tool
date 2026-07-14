import type { ScenarioEventBridgeFactory } from './event-bridge.js';
import type { ScenarioEventSink } from './event-bus.js';
import type { ObservedEvent, ObservedEventName, ObservedServiceName } from './event-types.js';
import type { DatabaseClient } from '@itw-conformance-tool/database';

interface EventRow {
  artifact_refs: string | null;
  correlation_id: string | null;
  diagnostic: string | null;
  error: string | null;
  http: string | null;
  id: string;
  monotonic_ms: number;
  name: string;
  request_id: string | null;
  scenario_id: string | null;
  service: string;
  timestamp: string;
  validation: string | null;
}

export interface CreateSqliteScenarioEventBridgeOptions {
  db: DatabaseClient;
  onError?: (error: unknown) => void;
  pollIntervalMs?: number;
}

function parseJsonField<T>(value: string | null): T | undefined {
  if (value === null) return undefined;
  return JSON.parse(value) as T;
}

function stringifyJsonField(value: unknown): string | null {
  return value === undefined ? null : JSON.stringify(value);
}

function rowToObservedEvent(row: EventRow): ObservedEvent {
  return {
    id: row.id,
    name: row.name as ObservedEventName,
    scenarioId: row.scenario_id,
    correlationId: row.correlation_id,
    service: row.service as ObservedServiceName,
    timestamp: row.timestamp,
    monotonicMs: Date.parse(row.timestamp),
    requestId: row.request_id ?? undefined,
    artifactRefs: parseJsonField(row.artifact_refs),
    diagnostic: parseJsonField(row.diagnostic),
    http: parseJsonField(row.http),
    error: parseJsonField(row.error),
    validation: parseJsonField(row.validation)
  } as ObservedEvent;
}

export class SqliteScenarioEventRepository implements ScenarioEventSink {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  async emit(event: ObservedEvent): Promise<void> {
    this.db.run(
      `INSERT OR IGNORE INTO conformance_events (
        id,
        name,
        scenario_id,
        correlation_id,
        service,
        timestamp,
        monotonic_ms,
        request_id,
        artifact_refs,
        diagnostic,
        http,
        error,
        validation
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        event.id,
        event.name,
        event.scenarioId,
        event.correlationId,
        event.service,
        event.timestamp,
        event.monotonicMs,
        event.requestId ?? null,
        stringifyJsonField(event.artifactRefs),
        stringifyJsonField(event.diagnostic),
        stringifyJsonField('http' in event ? event.http : undefined),
        stringifyJsonField('error' in event ? event.error : undefined),
        stringifyJsonField('validation' in event ? event.validation : undefined)
      ]
    );
  }

  listSince(startedAt: string): ObservedEvent[] {
    const rows = this.db.query<EventRow>(
      `SELECT
        id,
        name,
        scenario_id,
        correlation_id,
        service,
        timestamp,
        monotonic_ms,
        request_id,
        artifact_refs,
        diagnostic,
        http,
        error,
        validation
      FROM conformance_events
      WHERE timestamp >= ?
      ORDER BY timestamp ASC, id ASC`,
      [startedAt]
    );

    return rows.map(rowToObservedEvent);
  }
}

export function createSqliteScenarioEventBridge(
  options: CreateSqliteScenarioEventBridgeOptions
): ScenarioEventBridgeFactory {
  return ({ eventStore, startedAt }) => {
    const repository = new SqliteScenarioEventRepository(options.db);
    const seenEventIds = new Set(eventStore.all().map((event) => event.id));

    function poll(): void {
      try {
        for (const event of repository.listSince(startedAt)) {
          if (seenEventIds.has(event.id)) continue;
          seenEventIds.add(event.id);
          void eventStore.emit(event);
        }
      } catch (error) {
        options.onError?.(error);
      }
    }

    poll();
    const interval = setInterval(poll, options.pollIntervalMs ?? 250);
    interval.unref();

    return {
      dispose() {
        clearInterval(interval);
      }
    };
  };
}
