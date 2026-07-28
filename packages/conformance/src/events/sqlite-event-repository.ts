import { normalizeUrl } from '@itw-conformance-tool/utils';

import { getRequiredEventName } from '../scenarios/definitions.js';

import type {
  LocalServiceEndpoints,
  ProtocolObservedScenarioDefinition,
  RequiredEventEvidenceExpectation,
  RequiredEventExpectation,
  RequiredEventMatchValue
} from '../scenarios/definitions.js';
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

/**
 * Lists the event names a scenario declares: its entry event, its required
 * evidence, and the continuations it forbids. Forbidden names are included
 * because a negative scenario's verdict depends on observing them — an event
 * this bridge does not adopt never reaches the scenario's event store, so it
 * could neither trip `expectNone` nor be reported by the verdict engine.
 */
function scenarioDeclaredEventNames(definition: ProtocolObservedScenarioDefinition): ObservedEventName[] {
  return [
    definition.entryEvent,
    ...(definition.requiredEvents ?? []).map(getRequiredEventName),
    ...(definition.forbiddenEvents ?? []).map(getRequiredEventName)
  ];
}

/**
 * Checks that a SQLite event was emitted after the current interactive scenario
 * session started.
 */
function isPostStartEvent(event: ObservedEvent, startedAt: string): boolean {
  return Date.parse(event.timestamp) >= Date.parse(startedAt);
}

/**
 * Ensures pre-correlation evidence is not already bound to a different scenario
 * ID or protocol correlation ID.
 */
function isUncorrelatedEvent(event: ObservedEvent): boolean {
  return event.correlationId === null;
}

/**
 * Compares one diagnostic value against either an exact string expectation or a
 * normalized configured endpoint URL.
 */
function matchValueMatches(
  actual: unknown,
  expected: RequiredEventMatchValue,
  endpoints: LocalServiceEndpoints
): boolean {
  if (typeof expected === 'string') return actual === expected;
  if (expected.match !== 'normalized-url') return false;
  if (typeof actual !== 'string') return false;

  const endpoint = endpoints[expected.endpoint];
  if (!endpoint) return false;

  return normalizeUrl(actual) === normalizeUrl(endpoint);
}

/**
 * Verifies that every matcher configured for an expected required event matches
 * the observed event diagnostics.
 */
function requiredEventMatch(
  event: ObservedEvent,
  expectation: RequiredEventEvidenceExpectation,
  endpoints: LocalServiceEndpoints
): boolean {
  const match = expectation.match;
  if (!match) return true;

  return Object.entries(match).every(([key, expected]) =>
    matchValueMatches(event.diagnostic?.[key], expected, endpoints)
  );
}

function canAdoptUncorrelatedPostStartEvent(
  expectation: RequiredEventExpectation
): expectation is RequiredEventEvidenceExpectation {
  return typeof expectation !== 'string' && expectation.correlation === 'allow-uncorrelated-post-start';
}

/**
 * Allows a scenario to opt in to narrowly matched, post-start, uncorrelated
 * evidence from the same expectations used for verdict/order checks: its
 * required events, and the continuations it forbids.
 *
 * A forbidden expectation declared as a bare event name carries no service or
 * diagnostics to narrow by, so any post-start, uncorrelated occurrence of that
 * name is adopted — the scenario asked for every occurrence to count.
 */
function matchesScenarioEventEvidence(
  event: ObservedEvent,
  definition: ProtocolObservedScenarioDefinition,
  endpoints: LocalServiceEndpoints,
  startedAt: string
): boolean {
  if (!isUncorrelatedEvent(event)) return false;
  if (!isPostStartEvent(event, startedAt)) return false;
  if (!scenarioDeclaredEventNames(definition).includes(event.name)) return false;

  const matchesExpectation = (expectation: RequiredEventExpectation): boolean =>
    canAdoptUncorrelatedPostStartEvent(expectation)
      ? expectation.event === event.name &&
        expectation.service === event.service &&
        requiredEventMatch(event, expectation, endpoints)
      : expectation === event.name;

  return (
    (definition.requiredEvents ?? []).filter(canAdoptUncorrelatedPostStartEvent).some(matchesExpectation) ||
    (definition.forbiddenEvents ?? []).some(matchesExpectation)
  );
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
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        event.id,
        event.name,
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
  return ({ definition, endpoints, eventStore, startedAt }) => {
    const repository = new SqliteScenarioEventRepository(options.db);
    const seenEventIds = new Set(eventStore.all().map((event) => event.id));

    function belongsToScenario(event: ObservedEvent): boolean {
      return matchesScenarioEventEvidence(event, definition, endpoints, startedAt);
    }

    function poll(): void {
      try {
        for (const event of repository.listSince(startedAt)) {
          if (seenEventIds.has(event.id)) continue;
          seenEventIds.add(event.id);
          if (!belongsToScenario(event)) continue;

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
