import { compareEventOrder, isEventAfter } from '../events/event-store.js';
import { getForbiddenEventNames, getRequiredEventNames, hasVerdictRule } from '../scenarios/definitions.js';

import type { ObservedEvent, ObservedEventName } from '../events/event-types.js';
import type { ProtocolObservedScenarioDefinition } from '../scenarios/definitions.js';
import type { ScenarioOutcome, ScenarioTimingSummary } from './outcome.js';
import type { ArtifactValidationResult } from './rules.js';

export interface VerdictInput {
  definition: ProtocolObservedScenarioDefinition;
  events: ObservedEvent[];
  artifactValidationResults: ArtifactValidationResult[];
  timings: ScenarioTimingSummary;
}

export interface VerdictEngine {
  evaluate(input: VerdictInput): ScenarioOutcome;
}

interface RequiredEventOccurrenceMatch {
  name: ObservedEventName;
  event: ObservedEvent | undefined;
}

interface RequiredEventOrderViolation {
  expectedName: ObservedEventName;
  observedEvent: ObservedEvent;
  observedName: ObservedEventName;
}

/**
 * Assigns each declared required-event occurrence (in declaration order,
 * skipping the entry event's own name) to a distinct observed event of the
 * same name, so that repeated required-event declarations - e.g. two
 * `issuer.credential.requested` entries for a scenario that must observe two
 * separate Credential Requests - are each matched to a distinct occurrence
 * instead of both resolving to the same first-seen event.
 *
 * The i-th declared occurrence of a given name is assigned the i-th
 * chronological (`compareEventOrder`) observed occurrence of that name after
 * the entry event. A declared occurrence with no corresponding observed event
 * yields `event: undefined`, signalling a missing occurrence. Scenarios whose
 * required event names are all unique are unaffected: each name simply
 * resolves to its (only) first occurrence, matching prior behavior.
 */
function matchRequiredEventOccurrences(
  requiredEventNames: ObservedEventName[],
  events: ObservedEvent[],
  entry: ObservedEvent
): RequiredEventOccurrenceMatch[] {
  const occurrencesByName = new Map<ObservedEventName, ObservedEvent[]>();
  const consumedByName = new Map<ObservedEventName, number>();

  const matches: RequiredEventOccurrenceMatch[] = [];
  for (const name of requiredEventNames) {
    if (name === entry.name) continue;

    let occurrences = occurrencesByName.get(name);
    if (!occurrences) {
      occurrences = events.filter((event) => event.name === name && isEventAfter(event, entry)).sort(compareEventOrder);
      occurrencesByName.set(name, occurrences);
    }

    const consumed = consumedByName.get(name) ?? 0;
    matches.push({ name, event: occurrences[consumed] });
    consumedByName.set(name, consumed + 1);
  }

  return matches;
}

/**
 * Finds the first required-event occurrence that was observed before an
 * earlier-declared occurrence, when the scenario opts in to the
 * 'required-events-in-order' verdict rule. Only called once every declared
 * occurrence has already been matched to a distinct observed event (see
 * `matchRequiredEventOccurrences`), so unmatched (missing) occurrences are
 * simply skipped here - they are already reported as missing evidence.
 */
function findRequiredEventOrderViolation(
  requiredEventMatches: RequiredEventOccurrenceMatch[]
): RequiredEventOrderViolation | undefined {
  let previous: { event: ObservedEvent; name: ObservedEventName } | undefined;

  for (const match of requiredEventMatches) {
    const observedEvent = match.event;
    if (!observedEvent) continue;

    if (previous && isEventAfter(previous.event, observedEvent)) {
      return { expectedName: previous.name, observedEvent, observedName: match.name };
    }

    previous = { event: observedEvent, name: match.name };
  }

  return undefined;
}

export function createProtocolObservedVerdictEngine(): VerdictEngine {
  return {
    evaluate(input) {
      const requiredEventNames = getRequiredEventNames(input.definition.requiredEvents);
      const entry = input.events.find((event) => event.name === input.definition.entryEvent);
      if (!entry) {
        return {
          testCaseId: input.definition.id,
          verdict: 'INCONCLUSIVE',
          reason: 'The wallet did not enter the scenario; no protocol evidence was observed.',
          evidence: [],
          missingEvidence: [
            {
              eventName: input.definition.entryEvent,
              message: `Entry event was not observed: ${input.definition.entryEvent}`
            }
          ],
          forbiddenEvidence: [],
          timings: input.timings
        };
      }

      // Only events the scenario's own event bridge adopted reach this point, so
      // a forbidden expectation's `match` narrowing has already been applied
      // (see `matchesScenarioEventEvidence`); matching by name is enough here.
      const forbiddenEventNames = getForbiddenEventNames(input.definition.forbiddenEvents);
      const forbiddenEvents = input.events.filter(
        (event) => forbiddenEventNames.includes(event.name) && isEventAfter(event, entry)
      );
      if (forbiddenEvents.length > 0) {
        return {
          testCaseId: input.definition.id,
          verdict: 'FAIL',
          reason: 'The wallet continued the flow after receiving a non-conformant response.',
          evidence: [
            { eventId: entry.id, eventName: entry.name, message: 'Entry event observed.', timestamp: entry.timestamp }
          ],
          missingEvidence: [],
          forbiddenEvidence: forbiddenEvents.map((event) => ({
            artifactRefs: event.artifactRefs,
            eventId: event.id,
            eventName: event.name,
            message: `Forbidden event observed: ${event.name}`,
            timestamp: event.timestamp
          })),
          timings: input.timings
        };
      }

      const invalidArtifact = input.artifactValidationResults.find((result) => result.status === 'invalid');
      if (invalidArtifact) {
        return {
          testCaseId: input.definition.id,
          verdict: 'FAIL',
          reason: invalidArtifact.reason ?? `Artifact validation failed: ${invalidArtifact.expectationId}`,
          evidence: [],
          missingEvidence: [],
          forbiddenEvidence: [],
          timings: input.timings
        };
      }

      const requiredEventMatches = matchRequiredEventOccurrences(requiredEventNames, input.events, entry);
      const missingRequiredEvents = requiredEventMatches.filter((match) => !match.event).map((match) => match.name);
      if (missingRequiredEvents.length > 0) {
        const verdict = input.definition.missingRequiredEventPolicy === 'fail' ? 'FAIL' : 'INCONCLUSIVE';
        return {
          testCaseId: input.definition.id,
          verdict,
          reason: `Required protocol events were not observed: ${missingRequiredEvents.join(', ')}`,
          evidence: [
            { eventId: entry.id, eventName: entry.name, message: 'Entry event observed.', timestamp: entry.timestamp }
          ],
          missingEvidence: missingRequiredEvents.map((eventName) => ({
            eventName,
            message: `Required event was not observed: ${eventName}`
          })),
          forbiddenEvidence: [],
          timings: input.timings
        };
      }

      if (hasVerdictRule(input.definition, 'required-events-in-order')) {
        const violation = findRequiredEventOrderViolation(requiredEventMatches);
        if (violation) {
          return {
            testCaseId: input.definition.id,
            verdict: 'FAIL',
            reason: `Required events were observed out of order: "${violation.observedName}" was observed before its required predecessor "${violation.expectedName}".`,
            evidence: [
              {
                eventId: entry.id,
                eventName: entry.name,
                message: 'Entry event observed.',
                timestamp: entry.timestamp
              }
            ],
            missingEvidence: [
              {
                eventName: violation.observedName,
                message: `Required event "${violation.observedName}" was observed before its required predecessor "${violation.expectedName}".`
              }
            ],
            forbiddenEvidence: [],
            timings: input.timings
          };
        }
      }

      const evidenceEvents = [
        entry,
        ...requiredEventMatches
          .map((match) => match.event)
          .filter((event): event is ObservedEvent => event !== undefined)
      ];

      return {
        testCaseId: input.definition.id,
        verdict: 'PASS',
        reason: 'Entry event observed, required events were observed, and no forbidden continuation was observed.',
        evidence: evidenceEvents.map((event) => ({
          artifactRefs: event.artifactRefs,
          eventId: event.id,
          eventName: event.name,
          message: event.id === entry.id ? 'Entry event observed.' : `Required event observed: ${event.name}`,
          timestamp: event.timestamp
        })),
        missingEvidence: [],
        forbiddenEvidence: [],
        timings: input.timings
      };
    }
  };
}
