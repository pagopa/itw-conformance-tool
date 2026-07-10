import type { ObservedEventName } from '../events/event-types.js';

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

export interface ProtocolObservedScenarioDefinition {
  id: string;
  title: string;
  phase: ProtocolObservedPhase;
  automationMode: AutomationMode;
  services: LocalServiceName[];
  stimulus: StimulusDefinition;
  entryEvent: ObservedEventName;
  requiredEvents?: ObservedEventName[];
  forbiddenEvents?: ObservedEventName[];
  artifactExpectations?: ArtifactExpectation[];
  timeouts: TimeoutProfile;
  verdictRules: VerdictRule[];
  instructions: ScenarioInstructions;
  missingRequiredEventPolicy?: 'fail' | 'inconclusive';
  setup?: Record<string, unknown>;
}
