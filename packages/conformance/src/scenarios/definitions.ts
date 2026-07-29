import type { ObservedEventName, ObservedServiceName } from '../events/event-types.js';
import type { IssuerFaultProfile, RpFaultProfile, TrustAnchorFaultProfile } from '@itw-conformance-tool/faults';

export type ProtocolObservedPhase = 'ISSUANCE' | 'PRESENTATION' | 'WALLET_INSTANCE';

export type AutomationMode = 'interactive-protocol-observed';

export type LocalServiceName = 'credentialIssuer' | 'federation' | 'relyingParty' | 'walletProvider';
export type LocalServiceEndpoints = Partial<Record<LocalServiceName, string>>;

export type StimulusDefinition =
  | {
      type: 'credential-offer';
      credentialConfigurationId?: string;
      credentialConfigurationIds?: string[];
      delivery: ('deep-link' | 'qr')[];
    }
  | { type: 'manual-instruction'; text: string }
  | {
      type: 'presentation-request';
      delivery: ('deep-link' | 'qr')[];
      /**
       * Retrieval method advertised for the `request_uri` in the engagement.
       * Omitted leaves it unset, so a wallet defaults to `get` (WP_082);
       * `'post'` exercises the POST retrieval (WP_083).
       */
      requestUriMethod?: 'get' | 'post';
    }
  | { type: 'web-url'; delivery: ('deep-link' | 'qr')[] };

export type ScenarioStimulus =
  | { type: 'credential-offer'; uri: string; qrCode: string }
  | { type: 'manual-instruction'; text: string }
  | { type: 'presentation-request'; uri: string; qrCode: string }
  | { type: 'web-url'; url: string; qrCode?: string };

export interface TimeoutProfile {
  /**
   * How long to keep watching for forbidden events after the entry event
   * before concluding none occurred. Optional; falls back to `protocolStepMs`
   * when not set (see `resolveTimeoutProfile`).
   */
  forbiddenObservationMs?: number;
  /**
   * Max time to wait for each subsequent required event once the protocol
   * exchange has started (i.e. after the entry event has been observed).
   */
  protocolStepMs: number;
  /**
   * Max time to wait for the entry event, i.e. for the tester to perform the
   * manual action (e.g. scan the QR code / open the deep link) that kicks
   * off the wallet interaction.
   */
  testerActionMs: number;
  /**
   * Overall timeout for the Vitest test case running the scenario. Optional;
   * defaults to `testerActionMs + protocolStepMs` when not set.
   */
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

/**
 * An event whose observation after the entry event fails the scenario. It takes
 * the same shape as a required-event expectation so a negative scenario can
 * forbid one narrowly matched continuation (e.g. a request on a specific
 * endpoint) instead of every occurrence of an event name.
 */
export type ForbiddenEventExpectation = RequiredEventExpectation;

export interface IssuerRuntimeConfigSetup {
  batchIssuanceByDeferred: boolean;
}

export function getRequiredEventName(expectation: RequiredEventExpectation): ObservedEventName {
  return typeof expectation === 'string' ? expectation : expectation.event;
}

export function getRequiredEventNames(requiredEvents: RequiredEventExpectation[] | undefined): ObservedEventName[] {
  return (requiredEvents ?? []).map(getRequiredEventName);
}

export function getForbiddenEventNames(forbiddenEvents: ForbiddenEventExpectation[] | undefined): ObservedEventName[] {
  return (forbiddenEvents ?? []).map(getRequiredEventName);
}

/**
 * Checks whether a scenario declares a given verdict rule, so both the
 * interactive wait loop and the verdict engine can share a single source of
 * truth for whether required events must be observed in declaration order.
 */
export function hasVerdictRule(
  definition: Pick<ProtocolObservedScenarioDefinition, 'verdictRules'>,
  type: VerdictRule['type']
): boolean {
  return definition.verdictRules.some((rule) => rule.type === type);
}

/**
 * Typed scenario setup. `issuerFault` declares a Credential Issuer fault
 * profile, `rpFault` declares a Relying Party fault profile, and
 * `issuerConfig` declares an owned runtime configuration override; the runner
 * must activate each of them before showing the stimulus and deactivate them on
 * cleanup (see `IssuerFaultController` and `RpFaultController`).
 */
export interface ScenarioSetup {
  issuerConfig?: IssuerRuntimeConfigSetup;
  issuerFault?: IssuerFaultProfile;
  rpFault?: RpFaultProfile;
  trustAnchorFault?: TrustAnchorFaultProfile;
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
  forbiddenEvents?: ForbiddenEventExpectation[];
  artifactExpectations?: ArtifactExpectation[];
  timeouts: TimeoutProfile;
  verdictRules: VerdictRule[];
  instructions: ScenarioInstructions;
  missingRequiredEventPolicy?: 'fail' | 'inconclusive';
  setup?: ScenarioSetup;
}
