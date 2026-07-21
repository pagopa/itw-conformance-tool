import type { ObservedEventName, ObservedServiceName } from '../events/event-types.js';

export type ProtocolObservedPhase = 'ISSUANCE' | 'PRESENTATION' | 'WALLET_INSTANCE';

export type AutomationMode = 'interactive-protocol-observed';

export type LocalServiceName = 'credentialIssuer' | 'federation' | 'relyingParty' | 'walletProvider';
export type LocalServiceEndpoints = Partial<Record<LocalServiceName, string>>;

export type StimulusDefinition =
  | { type: 'credential-offer'; delivery: ('deep-link' | 'qr')[] }
  | { type: 'manual-instruction'; text: string }
  | { type: 'presentation-request'; delivery: ('deep-link' | 'qr')[] }
  | { type: 'web-url'; delivery: ('deep-link' | 'qr')[] };

export type ScenarioStimulus =
  | { type: 'credential-offer'; uri: string; qrCode: string }
  | { type: 'manual-instruction'; text: string }
  | { type: 'presentation-request'; uri: string; qrCode: string }
  | { type: 'web-url'; url: string; qrCode?: string };

export interface TimeoutProfile {
  forbiddenObservationMs?: number;
  protocolStepMs: number;
  testerActionMs: number;
  vitestTestMs?: number;
}

export interface ArtifactExpectation {
  event: ObservedEventName;
  expectationId?: string;
  validator: string;
}

export type VerdictRule =
  | { type: 'artifact-validation' }
  | { type: 'entry-event-required' }
  | { type: 'no-forbidden-events-after-entry' }
  | { type: 'required-events-in-order' };

export interface ScenarioInstructions {
  expectedBehavior: string;
  goal: string;
  prerequisites?: string[];
  steps?: string[];
}

export type RequiredEventMatchValue =
  | string
  | {
      endpoint: LocalServiceName;
      match: 'normalized-url';
    };

export interface RequiredEventEvidenceExpectation {
  event: ObservedEventName;
  service: ObservedServiceName;
  correlation?: 'allow-uncorrelated-post-start';
  match?: Record<string, RequiredEventMatchValue>;
}

export type RequiredEventExpectation = ObservedEventName | RequiredEventEvidenceExpectation;

export function getRequiredEventName(expectation: RequiredEventExpectation): ObservedEventName {
  return typeof expectation === 'string' ? expectation : expectation.event;
}

export function getRequiredEventNames(requiredEvents: RequiredEventExpectation[] | undefined): ObservedEventName[] {
  return (requiredEvents ?? []).map(getRequiredEventName);
}

export interface ProtocolObservedScenarioDefinition {
  id: string;
  title: string;
  phase: ProtocolObservedPhase;
  automationMode: AutomationMode;
  services: LocalServiceName[];
  stimulus: StimulusDefinition;
  entryEvent: ObservedEventName;
  requiredEvents?: RequiredEventExpectation[];
  forbiddenEvents?: ObservedEventName[];
  artifactExpectations?: ArtifactExpectation[];
  timeouts: TimeoutProfile;
  verdictRules: VerdictRule[];
  instructions: ScenarioInstructions;
  missingRequiredEventPolicy?: 'fail' | 'inconclusive';
  setup?: Record<string, unknown>;
}
