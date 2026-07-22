import { getRequiredEventNames, hasVerdictRule } from '../scenarios/definitions.js';

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

interface RequiredEventOrderViolation {
  expectedName: ObservedEventName;
  observedEvent: ObservedEvent;
  observedName: ObservedEventName;
}

/**
 * Finds the first required event that was observed before an earlier-declared
 * required event, when the scenario opts in to the 'required-events-in-order'
 * verdict rule. Only called once every required event's presence has already
 * been confirmed, so each name is guaranteed to have at least one occurrence
 * after the entry event.
 */
function findRequiredEventOrderViolation(
  requiredEventNames: ObservedEventName[],
  events: ObservedEvent[],
  entry: ObservedEvent
): RequiredEventOrderViolation | undefined {
  let previous: { event: ObservedEvent; name: ObservedEventName } | undefined;

  for (const name of requiredEventNames) {
    if (name === entry.name) continue;

    const firstOccurrence = events
      .filter((event) => event.name === name && event.monotonicMs > entry.monotonicMs)
      .sort((a, b) => a.monotonicMs - b.monotonicMs)[0];
    if (!firstOccurrence) continue;

    if (previous && firstOccurrence.monotonicMs < previous.event.monotonicMs) {
      return { expectedName: previous.name, observedEvent: firstOccurrence, observedName: name };
    }

    previous = { event: firstOccurrence, name };
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

      const forbiddenEvents = input.events.filter(
        (event) =>
          (input.definition.forbiddenEvents ?? []).includes(event.name) && event.monotonicMs > entry.monotonicMs
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

      const missingRequiredEvents = requiredEventNames.filter((name) => {
        if (name === entry.name) return false;
        return !input.events.some((event) => event.name === name && event.monotonicMs > entry.monotonicMs);
      });
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
        const violation = findRequiredEventOrderViolation(requiredEventNames, input.events, entry);
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
        ...requiredEventNames
          .filter((name) => name !== entry.name)
          .map((name) => input.events.find((event) => event.name === name && event.monotonicMs > entry.monotonicMs))
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
