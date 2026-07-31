import type {
  ForbiddenEventExpectation,
  ProtocolObservedScenarioDefinition,
  RequiredEventEvidenceExpectation,
  RequiredEventExpectation,
  TimeoutProfile
} from '../definitions.js';
import type { RpFaultProfile } from '@itw-conformance-tool/faults';

/**
 * Shared protocol evidence for the OpenID4VP remote presentation scenarios.
 *
 * The protocol correlationId mechanism is currently disabled, so every observed
 * event is emitted uncorrelated and has to be adopted as post-start evidence
 * narrowed by its diagnostics (`match`). Declaring each step once here keeps the
 * happy path and the negative paths matching the very same evidence.
 */

/** WP_078 / WP_084: the wallet fetches the Relying Party Entity Configuration. */
export const rpEntityConfigurationRequested: RequiredEventEvidenceExpectation = {
  event: 'rp.metadata.requested',
  label: 'Wallet contacted the Relying Party',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/.well-known/openid-federation' }
};

/** WP_079: Trust Chain resolution — the wallet fetches the Trust Anchor Entity Configuration. */
export const trustAnchorEntityConfigurationRequested: RequiredEventEvidenceExpectation = {
  event: 'federation.anchor.requested',
  label: 'Wallet contacted the Trust Anchor',
  service: 'federation',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/.well-known/openid-federation' }
};

/**
 * WP_078 / WP_079 / WP_080: the wallet fetches the subordinate statement about
 * the Relying Party from the Trust Anchor `/fetch` endpoint, which is also where
 * the Trust Marks are anchored.
 */
export const relyingPartySubordinateStatementRequested: RequiredEventEvidenceExpectation = {
  event: 'federation.fetch.requested',
  label: 'Wallet resolved the Relying Party trust statement',
  service: 'federation',
  correlation: 'allow-uncorrelated-post-start',
  match: {
    endpoint: '/fetch',
    sub: { endpoint: 'relyingParty', match: 'normalized-url' }
  }
};

/**
 * WP_082 / WP_083: the wallet retrieves the signed Request Object from the
 * `request_uri` endpoint, over GET when the engagement advertises no
 * `request_uri_method` and over POST when it advertises `post`.
 */
export function requestObjectRequested(method: 'GET' | 'POST'): RequiredEventEvidenceExpectation {
  return {
    event: 'rp.request_object.requested',
    label: `Wallet retrieved the presentation request object over ${method}`,
    service: 'relying-party',
    correlation: 'allow-uncorrelated-post-start',
    match: { endpoint: '/auth/request/:state', method }
  };
}

/**
 * WP_091 / WP_092 / WP_093 (+ a/b/c): the wallet posts the encrypted
 * Authorization Response carrying the vp_token to the `response_uri`. The
 * `outcome` diagnostic distinguishes it from an Authorization Error Response
 * sent to the same endpoint.
 */
export const authorizationResponseReceived: RequiredEventEvidenceExpectation = {
  event: 'rp.presentation_response.received',
  label: 'Wallet returned the presentation response',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/response', method: 'POST', outcome: 'response' }
};

/**
 * Anchors the response content checks (WP_092, WP_093, WP_093a/b/c): the RP
 * decrypted the response and validated the vp_token, its SD-JWT disclosures and
 * the Key Binding JWTs.
 */
export const vpTokenValidationSucceeded: RequiredEventEvidenceExpectation = {
  event: 'vp_token.validation.succeeded',
  label: 'Relying Party validated the VP token',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/response' }
};

/** WP_094: the wallet followed the RP-supplied redirect_uri to the attested callback endpoint. */
export const attestedRedirectFollowed: RequiredEventEvidenceExpectation = {
  event: 'rp.redirect.followed',
  label: 'Wallet followed the Relying Party redirect',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/callback', method: 'GET' }
};

/** WP_090: the wallet reported a rejected Request Object to the `response_uri`. */
export const authorizationErrorResponseReceived: RequiredEventEvidenceExpectation = {
  event: 'rp.presentation_error.received',
  label: 'Wallet reported the presentation request error',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/response', method: 'POST' }
};

/** Evidence that the Relying Party served the artifact the scenario's fault mutated. */
export function rpFaultApplied(
  endpoint: string,
  faultProfileType: RpFaultProfile['type'],
  match: Record<string, string> = {}
): RequiredEventEvidenceExpectation {
  return {
    event: 'rp.fault.applied',
    label: `Relying Party served the ${faultProfileType} test artifact`,
    service: 'relying-party',
    correlation: 'allow-uncorrelated-post-start',
    match: { endpoint, faultProfileType, ...match }
  };
}

/**
 * The wallet retrieved the Request Object even though the scenario made it
 * unusable (an unattested `request_uri`, an untrusted federation position, or a
 * Relying Party the federation does not authorize): continuing to this step is
 * the observable failure.
 */
export const requestObjectRetrievalForbidden: ForbiddenEventExpectation = {
  event: 'rp.request_object.requested',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/request/:state' }
};

/**
 * The wallet sent an actual Authorization Response — not an Authorization Error
 * Response — for a Request Object it should have rejected. Matching on `outcome`
 * keeps the WP_090 error report allowed while still failing a completed
 * presentation.
 */
export const authorizationResponseForbidden: ForbiddenEventExpectation = {
  event: 'rp.presentation_response.received',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/response', outcome: 'response' }
};

/**
 * The wallet followed a `redirect_uri` the Relying Party never attested
 * (WP_094a).
 *
 * It matches the same endpoint as `attestedRedirectFollowed` on purpose: the
 * fault moves the attested `redirect_uris` list, not the endpoint the
 * Authorization Response points at, so the very follow that proves conformance
 * in the happy path proves a missing check here.
 */
export const unattestedRedirectFollowForbidden: ForbiddenEventExpectation = {
  event: 'rp.redirect.followed',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/callback', method: 'GET' }
};

/**
 * Timeouts shared by the presentation scenarios. `forbiddenObservationMs` is
 * long enough for a conforming wallet to fetch, parse and reject the defective
 * artifact — and for a non-conforming one to reveal itself by continuing —
 * before the runner concludes the forbidden step never happened.
 */
export const presentationTimeouts: TimeoutProfile = {
  testerActionMs: 300_000,
  protocolStepMs: 60_000,
  forbiddenObservationMs: 30_000,
  vitestTestMs: 420_000
};

export interface NegativePresentationInstructions {
  expectedBehavior: string;
  goal: string;
  /** Short operator-facing purpose shown near the scenario title. */
  summary?: string;
  /** Tester actions between acquiring the engagement and the verdict. */
  observation: string[];
}

export interface NegativePresentationScenarioOptions {
  delivery?: ('deep-link' | 'qr')[];
  forbiddenEvents: ForbiddenEventExpectation[];
  id: string;
  instructions: NegativePresentationInstructions;
  missingRequiredEventPolicy?: 'fail' | 'inconclusive';
  /** Evidence expected after the entry event, in observation order. */
  requiredEvents: RequiredEventExpectation[];
  requestUriMethod?: 'get' | 'post';
  rpFault: RpFaultProfile;
  timeouts?: Partial<TimeoutProfile>;
  title: string;
}

/**
 * Builds a negative remote-presentation scenario: the Relying Party serves one
 * defective artifact and the wallet is expected to stop instead of completing
 * the flow. Every such scenario shares the same shape — a Relying Party fault
 * activated before the engagement is shown, the Entity Configuration fetch as
 * the entry event, and a forbidden continuation observed for a bounded window —
 * so only the fault, the evidence and the tester-facing texts differ.
 */
export function createNegativePresentationScenario(
  options: NegativePresentationScenarioOptions
): ProtocolObservedScenarioDefinition {
  const delivery = options.delivery ?? ['deep-link'];
  const isSameDevice = delivery.includes('deep-link');

  return {
    id: options.id,
    title: options.title,
    phase: 'PRESENTATION',
    automationMode: 'interactive-protocol-observed',
    services: ['relyingParty', 'federation'],
    stimulus: {
      type: 'presentation-request',
      delivery,
      ...(options.requestUriMethod ? { requestUriMethod: options.requestUriMethod } : {})
    },
    setup: { rpFault: options.rpFault },
    entryEvent: 'rp.metadata.requested',
    requiredEvents: [rpEntityConfigurationRequested, ...options.requiredEvents],
    forbiddenEvents: options.forbiddenEvents,
    timeouts: { ...presentationTimeouts, ...options.timeouts },
    verdictRules: [
      { type: 'entry-event-required' },
      { type: 'required-events-in-order' },
      { type: 'no-forbidden-events-after-entry' }
    ],
    instructions: {
      goal: options.instructions.goal,
      expectedBehavior: options.instructions.expectedBehavior,
      summary: options.instructions.summary,
      prerequisites: [
        'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
        isSameDevice
          ? 'The wallet can open presentation request deep links on the same device (same-device flow).'
          : 'A second device can scan the presentation request QR payload (cross-device flow).',
        'Run the test from the workspace root, where config.ini and the compiled local services are available.',
        'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
      ],
      steps: [
        isSameDevice
          ? 'Open the presentation request with the Wallet Instance on the same device.'
          : 'Scan the presentation request QR payload with the Wallet Instance.',
        ...options.instructions.observation,
        'Keep the wallet and this command running until the scenario completes.'
      ]
    },
    missingRequiredEventPolicy: options.missingRequiredEventPolicy ?? 'inconclusive'
  };
}
