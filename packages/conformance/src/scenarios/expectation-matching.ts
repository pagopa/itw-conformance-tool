import { normalizeUrl } from '@itw-conformance-tool/utils';

import type { ObservedEvent } from '../events/event-types.js';
import type {
  LocalServiceEndpoints,
  RequiredEventEvidenceExpectation,
  RequiredEventExpectation,
  RequiredEventMatchValue
} from './definitions.js';

/**
 * Compares one diagnostic value against either an exact string expectation or a
 * normalized configured endpoint URL.
 */
function matchValueMatches(
  actual: unknown,
  expected: RequiredEventMatchValue,
  endpoints: LocalServiceEndpoints
): boolean {
  if (typeof expected === 'number' || typeof expected === 'boolean') return actual === expected;
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

/**
 * Checks whether an observed event satisfies a declared required/forbidden
 * event expectation: the event name always must match, and when the
 * expectation carries a service and/or diagnostic `match` narrowing (i.e. it
 * is a `RequiredEventEvidenceExpectation` rather than a bare event name),
 * the observed event's service and diagnostic payload must satisfy them too.
 *
 * This is the single source of truth for expectation matching, shared by
 * scenario-progress tracking (`scenario-runner.ts`) and event-bridge adoption
 * (`sqlite-event-repository.ts`), so a duplicated event name with distinct
 * `match` criteria - e.g. an `authorization_code` vs. `refresh_token` token
 * request - can never be mistaken for the wrong declared occurrence.
 */
export function matchesRequiredEventExpectation(
  event: ObservedEvent,
  expectation: RequiredEventExpectation,
  endpoints: LocalServiceEndpoints
): boolean {
  if (typeof expectation === 'string') return expectation === event.name;

  return (
    expectation.event === event.name &&
    expectation.service === event.service &&
    requiredEventMatch(event, expectation, endpoints)
  );
}
