import type { ObservedEvent } from '../events/event-types.js';
import type { ProtocolObservedScenarioDefinition } from '../scenarios/definitions.js';
import type { ScenarioOutcome, ScenarioTimingSummary } from './outcome.js';
import type { ArtifactValidationResult } from './rules.js';

export interface VerdictInput {
  definition: ProtocolObservedScenarioDefinition;
  events: ObservedEvent[];
  artifactValidationResults: ArtifactValidationResult[];
  timings: ScenarioTimingSummary;
  scenarioId: string;
}

export interface VerdictEngine {
  evaluate(input: VerdictInput): ScenarioOutcome;
}

export function createProtocolObservedVerdictEngine(): VerdictEngine {
  return {
    evaluate(input) {
      const entry = input.events.find((event) => event.name === input.definition.entryEvent);
      if (!entry) {
        return {
          scenarioId: input.scenarioId,
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
          scenarioId: input.scenarioId,
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
          scenarioId: input.scenarioId,
          testCaseId: input.definition.id,
          verdict: 'FAIL',
          reason: invalidArtifact.reason ?? `Artifact validation failed: ${invalidArtifact.expectationId}`,
          evidence: [],
          missingEvidence: [],
          forbiddenEvidence: [],
          timings: input.timings
        };
      }

      const missingRequiredEvents = (input.definition.requiredEvents ?? []).filter((name) => {
        if (name === entry.name) return false;
        return !input.events.some((event) => event.name === name && event.monotonicMs > entry.monotonicMs);
      });
      if (missingRequiredEvents.length > 0) {
        const verdict = input.definition.missingRequiredEventPolicy === 'fail' ? 'FAIL' : 'INCONCLUSIVE';
        return {
          scenarioId: input.scenarioId,
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

      const evidenceEvents = [
        entry,
        ...(input.definition.requiredEvents ?? [])
          .filter((name) => name !== entry.name)
          .map((name) => input.events.find((event) => event.name === name && event.monotonicMs > entry.monotonicMs))
          .filter((event): event is ObservedEvent => event !== undefined)
      ];

      return {
        scenarioId: input.scenarioId,
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
