import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import type { ArtifactRef } from '../artifacts/artifact-store.js';
import type {
  HttpRequestDetails,
  HttpResponseDetails,
  ObservedErrorDetails,
  ObservedEvent,
  ObservedEventName,
  ObservedServiceName
} from './event-types.js';

export interface ScenarioEventSink {
  emit(event: ObservedEvent): Promise<void> | void;
}

export interface ObservedEventInput {
  name: ObservedEventName;
  correlationId: string | null;
  service: ObservedServiceName;
  requestId?: string;
  artifactRefs?: ArtifactRef[];
  diagnostic?: Record<string, unknown>;
  http?: HttpRequestDetails | HttpResponseDetails;
  error?: ObservedErrorDetails;
  validation?: Record<string, unknown>;
}

/**
 * Wall-clock timestamp with microsecond resolution, as an ISO 8601 string with
 * six fractional digits.
 *
 * Millisecond resolution is not enough to order observed events: a single
 * request handler routinely emits two events (the protocol event and the fault
 * evidence that follows it) inside the same millisecond, and consumers compare
 * timestamps to decide whether one event happened after another — a scenario's
 * ordered required-event evidence depends on it. `performance.timeOrigin +
 * performance.now()` keeps sub-millisecond precision and is monotonic within the
 * emitting process, while remaining a wall-clock value that stays comparable
 * across the local services. The string is fixed width, so lexicographic order
 * is chronological order, and `Date.parse` still reads it (truncated to
 * milliseconds).
 */
function highResolutionTimestamp(): string {
  const nowMs = performance.timeOrigin + performance.now();
  const wholeMs = Math.floor(nowMs);
  const microseconds = Math.round((nowMs - wholeMs) * 1000);

  return `${new Date(wholeMs).toISOString().slice(0, -1)}${String(Math.min(microseconds, 999)).padStart(3, '0')}Z`;
}

export function createObservedEvent(input: ObservedEventInput): ObservedEvent {
  return {
    id: randomUUID(),
    timestamp: highResolutionTimestamp(),
    monotonicMs: performance.now(),
    ...input
  } as ObservedEvent;
}
