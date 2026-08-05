import type { ObservedEventName } from '../../events/event-types.js';
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
 *
 * Which evidence a scenario may expect at all depends on the Client Identifier
 * Prefix its engagement announces (`stimulus.clientIdPrefix`). Under the IT
 * Wallet 1.3 default, `x509_hash`, the wallet verifies the Request Object with
 * the `x5c` certificate chain and reads the Verifier metadata from the inline
 * `client_metadata`: it has no reason to fetch the Entity Configuration, the
 * Trust Anchor or a subordinate statement, and it could not do so before
 * retrieving the Request Object anyway — the `client_id` is a certificate hash,
 * so the entity identifier only reaches the wallet in the `iss` claim. Only an
 * `openid_federation` engagement makes the federation discovery observable,
 * which is why `federationDiscoveryEvidence` and the Entity-Configuration faults
 * belong exclusively to scenarios that ask for that prefix.
 */

/** Trust model an engagement can announce; the Relying Party defaults to `x509_hash`. */
export type PresentationClientIdPrefix = 'openid_federation' | 'x509_hash';

/**
 * WP_078 / WP_084: the wallet fetches the Relying Party Entity Configuration.
 * Only an `openid_federation` engagement points it there.
 */
export const rpEntityConfigurationRequested: RequiredEventEvidenceExpectation = {
  event: 'rp.metadata.requested',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/.well-known/openid-federation' }
};

/** WP_079: Trust Chain resolution — the wallet fetches the Trust Anchor Entity Configuration. */
export const trustAnchorEntityConfigurationRequested: RequiredEventEvidenceExpectation = {
  event: 'federation.anchor.requested',
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
  service: 'federation',
  correlation: 'allow-uncorrelated-post-start',
  match: {
    endpoint: '/fetch',
    sub: { endpoint: 'relyingParty', match: 'normalized-url' }
  }
};

/**
 * The federation discovery a wallet performs when — and only when — the
 * engagement carries the `openid_federation` Client Identifier Prefix: the
 * Relying Party Entity Configuration, the Trust Anchor Entity Configuration and
 * the subordinate statement that binds the two.
 */
export const federationDiscoveryEvidence: RequiredEventEvidenceExpectation[] = [
  rpEntityConfigurationRequested,
  trustAnchorEntityConfigurationRequested,
  relyingPartySubordinateStatementRequested
];

/**
 * The first Relying Party call each trust model produces, and therefore the
 * event that opens the observation window.
 *
 * A federation engagement starts at the Entity Configuration fetch, which is
 * the wallet's first act. An `x509_hash` engagement starts at the Request Object
 * retrieval: everything the wallet needs travels in the Request Object, so that
 * fetch is the first thing the Relying Party sees.
 *
 * An inlined Trust Chain does not move it: the engagement `client_id` names the
 * entity, so the wallet resolves the Relying Party before it has any Request
 * Object header to read.
 */
export function presentationEntryEvent(clientIdPrefix: PresentationClientIdPrefix): ObservedEventName {
  return clientIdPrefix === 'openid_federation' ? 'rp.metadata.requested' : 'rp.request_object.requested';
}

/**
 * WP_082 / WP_083: the wallet retrieves the signed Request Object from the
 * `request_uri` endpoint, over GET when the engagement advertises no
 * `request_uri_method` and over POST when it advertises `post`.
 *
 * `clientIdPrefix` narrows the evidence to a Request Object served for a given
 * trust model. WP_084 needs it: what proves the wallet resolved the key through
 * the federation is that the artifact it accepted carried no `x5c` at all.
 *
 * `inlineTrustChain` narrows it further, to a Request Object whose header
 * carried the Trust Chain by value — the only way a verdict can claim the
 * wallet had the Entity Configuration in hand without having fetched it.
 */
export function requestObjectRequested(
  method: 'GET' | 'POST',
  clientIdPrefix?: PresentationClientIdPrefix,
  options: { inlineTrustChain?: boolean } = {}
): RequiredEventEvidenceExpectation {
  return {
    event: 'rp.request_object.requested',
    service: 'relying-party',
    correlation: 'allow-uncorrelated-post-start',
    match: {
      endpoint: '/auth/request/:state',
      method,
      ...(clientIdPrefix ? { clientIdPrefix, hasX5c: clientIdPrefix === 'x509_hash' } : {}),
      ...(options.inlineTrustChain === undefined ? {} : { hasTrustChain: options.inlineTrustChain })
    }
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
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/auth/response' }
};

/** WP_094: the wallet followed the RP-supplied redirect_uri to the attested callback endpoint. */
export const attestedRedirectFollowed: RequiredEventEvidenceExpectation = {
  event: 'rp.redirect.followed',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/callback', method: 'GET' }
};

/** WP_117: the wallet sent a valid Erasure Request to the attested Relying Party endpoint. */
export const erasureRequestAccepted: RequiredEventEvidenceExpectation = {
  event: 'rp.erasure.requested',
  service: 'relying-party',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/erasure', method: 'GET', outcome: 'accepted' }
};

/** WP_090: the wallet reported a rejected Request Object to the `response_uri`. */
export const authorizationErrorResponseReceived: RequiredEventEvidenceExpectation = {
  event: 'rp.presentation_error.received',
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
  /** Tester actions between acquiring the engagement and the verdict. */
  observation: string[];
}

export interface NegativePresentationScenarioOptions {
  /**
   * Trust model the engagement announces. Defaults to the Relying Party's
   * `x509_hash`; scenarios whose fault mutates the Entity Configuration must ask
   * for `openid_federation`, since nothing else makes a wallet read it.
   */
  clientIdPrefix?: PresentationClientIdPrefix;
  delivery?: ('deep-link' | 'qr')[];
  forbiddenEvents: ForbiddenEventExpectation[];
  id: string;
  /**
   * Hands the wallet the Trust Chain inside the Request Object header instead of
   * leaving it to resolve one for the signature check. Only an
   * `openid_federation` engagement honours it.
   *
   * It does not relieve the wallet of federation discovery: the engagement
   * `client_id` names the entity, so a wallet still resolves the Relying Party
   * before it has a Request Object header to read. What it changes is what the
   * header itself has to offer once retrieved.
   */
  inlineTrustChain?: boolean;
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
 * activated before the engagement is shown, the first Relying Party call as the
 * entry event, and a forbidden continuation observed for a bounded window — so
 * only the trust model, the fault, the evidence and the tester-facing texts
 * differ.
 *
 * The entry event follows the trust model, because forbidden events are only
 * counted after it: a federation scenario opens at the Entity Configuration
 * fetch it is about, while an `x509_hash` scenario opens at the Request Object
 * retrieval, the first call such a wallet makes.
 */
export function createNegativePresentationScenario(
  options: NegativePresentationScenarioOptions
): ProtocolObservedScenarioDefinition {
  const delivery = options.delivery ?? ['deep-link'];
  const isSameDevice = delivery.includes('deep-link');
  const clientIdPrefix = options.clientIdPrefix ?? 'x509_hash';
  const isFederation = clientIdPrefix === 'openid_federation';

  return {
    id: options.id,
    title: options.title,
    phase: 'PRESENTATION',
    automationMode: 'interactive-protocol-observed',
    // The Trust Anchor is started for every presentation scenario: the Relying
    // Party derives its own Entity Configuration and Trust Mark from it even
    // when the trust model under test never makes a wallet read them.
    services: ['relyingParty', 'federation'],
    stimulus: {
      type: 'presentation-request',
      clientIdPrefix,
      delivery,
      ...(options.inlineTrustChain ? { inlineTrustChain: true } : {}),
      ...(options.requestUriMethod ? { requestUriMethod: options.requestUriMethod } : {})
    },
    setup: { rpFault: options.rpFault },
    entryEvent: presentationEntryEvent(clientIdPrefix),
    requiredEvents: isFederation ? [rpEntityConfigurationRequested, ...options.requiredEvents] : options.requiredEvents,
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
      prerequisites: [
        'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
        isSameDevice
          ? 'The wallet can open presentation request deep links on the same device (same-device flow).'
          : 'A second device can scan the presentation request QR payload (cross-device flow).',
        'Run the test from the workspace root, where config.ini and the compiled local services are available.',
        'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
      ],
      steps: [
        `Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services, activates the ${options.rpFault.type} fault on the Relying Party, and waits for their readiness.`,
        isSameDevice
          ? 'Open the printed presentation request deep link with the Wallet Instance on the same device.'
          : 'Scan the printed presentation request QR payload with the Wallet Instance.',
        ...options.instructions.observation,
        'The runner concludes automatically once the required evidence is recorded and the negative-observation window elapses without the wallet performing the forbidden step.'
      ]
    },
    missingRequiredEventPolicy: options.missingRequiredEventPolicy ?? 'inconclusive'
  };
}
