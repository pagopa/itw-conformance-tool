import type { ArtifactRef } from '../artifacts/artifact-store.js';
import type { ObservedEventName } from '../events/event-types.js';

export type ScenarioVerdict = 'FAIL' | 'INCONCLUSIVE' | 'PASS';

export interface EvidenceItem {
  artifactRefs?: ArtifactRef[];
  eventId?: string;
  eventName?: ObservedEventName;
  message: string;
  timestamp?: string;
}

export interface MissingEvidenceItem {
  eventName?: ObservedEventName;
  expectationId?: string;
  message: string;
}

export interface ScenarioTimingSummary {
  completedAt?: string;
  durationMs?: number;
  startedAt: string;
}

export interface ScenarioOutcome {
  scenarioId: string;
  testCaseId: string;
  verdict: ScenarioVerdict;
  reason: string;
  evidence: EvidenceItem[];
  missingEvidence: MissingEvidenceItem[];
  forbiddenEvidence: EvidenceItem[];
  timings: ScenarioTimingSummary;
}
