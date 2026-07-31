import type { ObservedEventName, ObservedServiceName } from '../events/event-types.js';
import type { IssuerFaultProfile, RpFaultProfile, TrustAnchorFaultProfile } from '@itw-conformance-tool/faults';

export type ProtocolObservedPhase = 'ISSUANCE' | 'PRESENTATION' | 'WALLET_INSTANCE';

export type AutomationMode = 'interactive-protocol-observed';

export type LocalServiceName = 'credentialIssuer' | 'federation' | 'relyingParty' | 'walletProvider';
export type LocalServiceEndpoints = Partial<Record<LocalServiceName, string>>;

/** How a scenario hands its engagement to the wallet: a scannable QR code, a
 * deep link opened on the wallet's device, or both. */
export type StimulusDelivery = 'deep-link' | 'qr';

export type StimulusDefinition =
  | {
      type: 'credential-offer';
      credentialConfigurationId?: string;
      credentialConfigurationIds?: string[];
      delivery: StimulusDelivery[];
    }
  | { type: 'manual-instruction'; text: string }
  | {
      type: 'presentation-request';
      /**
       * Trust mechanism the engagement announces through its Client Identifier
       * Prefix, and therefore the one the wallet is expected to use.
       *
       * Omitted, the Relying Party applies its IT Wallet 1.3 default,
       * `x509_hash`: the wallet verifies the Request Object with the `x5c`
       * certificate chain and reads the Verifier metadata from
       * `client_metadata`, so it has no reason to touch the federation.
       * `'openid_federation'` is what makes the Trust Chain, the Trust Marks
       * and the attested endpoint lists observable, and it must be set by every
       * scenario whose verdict depends on them.
       */
      clientIdPrefix?: 'openid_federation' | 'x509_hash';
      delivery: StimulusDelivery[];
      /**
       * Retrieval method advertised for the `request_uri` in the engagement.
       * Omitted leaves it unset, so a wallet defaults to `get` (WP_082);
       * `'post'` exercises the POST retrieval (WP_083).
       */
      requestUriMethod?: 'get' | 'post';
    }
  | { type: 'web-url'; delivery: StimulusDelivery[] };

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
  | boolean
  | number
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
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  statusList?: {
    bits: 4;
    ttlSeconds?: number;
    values: number[];
  };
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
