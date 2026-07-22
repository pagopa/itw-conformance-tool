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

export function createObservedEvent(input: ObservedEventInput): ObservedEvent {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    monotonicMs: performance.now(),
    ...input
  } as ObservedEvent;
}
