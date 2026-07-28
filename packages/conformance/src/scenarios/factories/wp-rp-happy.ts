import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * Happy-path OpenID4VP remote presentation flow.
 *
 * A single interactive run exercises every RP/Trust-Anchor-observable endpoint
 * call of the remote flow, so one flow satisfies many Wallet Solution Test
 * Matrix cases at once (see the test suite that maps WP_076..WP_094 onto this
 * scenario). Only the happy-path, protocol-observable cases are covered here;
 * the negative cases (WP_081, WP_085, WP_086, WP_087, WP_090, WP_091a, WP_094a)
 * and the UI-only cases (WP_088, WP_089x) require dedicated unhappy-path
 * scenarios.
 *
 * This is a same-device flow (deep-link engagement): the wallet redirects the
 * user-agent back to the RP at the end, which is what makes the WP_094 redirect
 * observable. It therefore covers WP_076 (deep-link reception) rather than the
 * mutually exclusive WP_077 (QR / cross-device reception).
 *
 * The protocol correlationId mechanism is currently disabled, so every observed
 * event — the federation-discovery calls and the later RP-route calls alike — is
 * emitted uncorrelated and adopted as post-start evidence narrowed by its
 * diagnostics (`match`).
 */
export const wpRpHappyScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_RP_HAPPY',
  title: 'Happy Path: Wallet Instance presents a credential to a Relying Party',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty', 'federation'],
  stimulus: {
    // WP_076 (deep-link) is chosen over the mutually exclusive WP_077 (QR): a
    // deep-link engagement drives a same-device flow, so the wallet performs the
    // WP_094 user-agent redirect that a cross-device (QR) flow would not.
    type: 'presentation-request',
    delivery: ['deep-link']
  },
  entryEvent: 'rp.metadata.requested',
  requiredEvents: [
    // WP_078 / WP_084: the wallet fetches the Relying Party Entity Configuration
    // (its OpenID Federation endpoint) to obtain metadata and verifier keys.
    {
      event: 'rp.metadata.requested',
      service: 'relying-party',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
    },
    // WP_079: Trust Chain resolution — the wallet fetches the Trust Anchor
    // Entity Configuration.
    {
      event: 'federation.anchor.requested',
      service: 'federation',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
    },
    // WP_078 / WP_079 / WP_080: the wallet fetches the subordinate statement
    // about the Relying Party from the Trust Anchor `/fetch` endpoint, which is
    // also where the Trust Marks are anchored.
    {
      event: 'federation.fetch.requested',
      service: 'federation',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/fetch',
        sub: { endpoint: 'relyingParty', match: 'normalized-url' }
      }
    },
    // WP_076 / WP_082: the wallet retrieves the signed Request Object via HTTP
    // GET on the request_uri endpoint (the RP advertises no request_uri_method,
    // so GET is used; WP_082 is chosen over the mutually exclusive WP_083 POST).
    // Adopted as uncorrelated post-start evidence narrowed by the GET method on
    // the request_uri endpoint (WP_082 is chosen over the POST WP_083).
    {
      event: 'rp.request_object.requested',
      service: 'relying-party',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/auth/request/:state', method: 'GET' }
    },
    // WP_091 / WP_092 / WP_093 (+ a/b/c): the wallet posts the encrypted
    // Authorization Response with the vp_token to the response_uri.
    {
      event: 'rp.presentation_response.received',
      service: 'relying-party',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/auth/response', method: 'POST' }
    },
    // Anchors the response content checks (WP_092, WP_093, WP_093a/b/c): the RP
    // decrypts the response and validates the vp_token, its SD-JWT disclosures,
    // and the Key Binding JWTs.
    {
      event: 'vp_token.validation.succeeded',
      service: 'relying-party',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/auth/response' }
    },
    // WP_094: the wallet follows the RP-supplied redirect_uri, hitting the
    // instrumented `/callback/:state` endpoint via HTTP GET.
    {
      event: 'rp.redirect.followed',
      service: 'relying-party',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/callback/:state', method: 'GET' }
    }
  ],
  forbiddenEvents: ['vp_token.validation.failed'],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    forbiddenObservationMs: 5_000,
    vitestTestMs: 330_000
  },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance completes a full OpenID4VP remote presentation: it discovers and trusts the Relying Party through the federation, retrieves and validates the signed Request Object, and returns an encrypted Authorization Response containing the requested credential.',
    expectedBehavior:
      'After acquiring the presentation request, the wallet resolves the Relying Party Entity Configuration and Trust Chain from the Trust Anchor, retrieves the signed Request Object from the request_uri endpoint, posts an encrypted Authorization Response with a vp_token to the response_uri, and follows the returned redirect_uri.',
    prerequisites: [
      'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
      'The wallet can open presentation request deep links on the same device (same-device flow).',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services and waits for their readiness.',
      'Open the printed presentation request deep link with the Wallet Instance on the same device.',
      'Allow the wallet to resolve the Relying Party federation trust chain and retrieve the Request Object.',
      'Approve the disclosure of the requested attributes in the wallet.',
      'The runner passes once the Relying Party receives a valid Authorization Response and the wallet follows the redirect_uri back to the Relying Party.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
