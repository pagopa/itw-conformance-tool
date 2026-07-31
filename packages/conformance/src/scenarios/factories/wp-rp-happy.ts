import {
  attestedRedirectFollowed,
  authorizationResponseReceived,
  presentationEntryEvent,
  presentationTimeouts,
  requestObjectRequested,
  vpTokenValidationSucceeded
} from './presentation-evidence.js';

import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * Happy-path OpenID4VP remote presentation flow, same-device with a GET Request
 * Object retrieval.
 *
 * A single interactive run exercises every RP-observable endpoint call of the
 * remote flow, so one flow satisfies many Wallet Solution Test Matrix cases at
 * once (see the test suite that maps WP_076..WP_094 onto this scenario). The
 * mutually exclusive variants are covered by `wpRpHappyPostScenario` (QR
 * engagement, POST retrieval), and the negative cases by the dedicated
 * unhappy-path scenarios; the UI-only cases (WP_088, WP_089x) remain out of
 * scope for a protocol-observed tool.
 *
 * This is a same-device flow (deep-link engagement): the wallet redirects the
 * user-agent back to the RP at the end, which is what makes the WP_094 redirect
 * observable. It therefore covers WP_076 (deep-link reception) rather than the
 * mutually exclusive WP_077 (QR / cross-device reception).
 *
 * The engagement uses the IT Wallet 1.3 nominal trust model, `x509_hash`: the
 * wallet verifies the Request Object against the `x5c` certificate chain and
 * takes the Verifier metadata from the inline `client_metadata`, so no
 * federation call is expected — and none could come first, since the `client_id`
 * is a certificate hash that names no entity. The federation discovery
 * (WP_078/WP_079/WP_080) belongs to the scenarios that ask for the
 * `openid_federation` prefix, starting with `wp084Scenario`.
 *
 * The protocol correlationId mechanism is currently disabled, so every observed
 * event is emitted uncorrelated and adopted as post-start evidence narrowed by
 * its diagnostics (`match`); see `presentation-evidence.ts`.
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
    clientIdPrefix: 'x509_hash',
    delivery: ['deep-link']
  },
  // The Request Object retrieval is the first call an `x509_hash` wallet makes.
  entryEvent: presentationEntryEvent('x509_hash'),
  requiredEvents: [
    // WP_076 / WP_082: the engagement advertises no request_uri_method, so the
    // wallet retrieves the Request Object over GET (WP_082 is chosen over the
    // mutually exclusive WP_083 POST).
    requestObjectRequested('GET', 'x509_hash'),
    authorizationResponseReceived,
    vpTokenValidationSucceeded,
    attestedRedirectFollowed
  ],
  forbiddenEvents: ['vp_token.validation.failed', 'rp.presentation_error.received'],
  timeouts: { ...presentationTimeouts, forbiddenObservationMs: 5_000, vitestTestMs: 330_000 },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance completes a full OpenID4VP remote presentation: it retrieves the signed Request Object, validates it against the certificate chain the x509_hash client_id commits to, and returns an encrypted Authorization Response containing the requested credential.',
    expectedBehavior:
      'After acquiring the presentation request, the wallet retrieves the signed Request Object from the request_uri endpoint, verifies it with the x5c certificate chain whose leaf hashes to the engagement client_id, posts an encrypted Authorization Response with a vp_token to the response_uri, and follows the returned redirect_uri.',
    prerequisites: [
      'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
      'The wallet can open presentation request deep links on the same device (same-device flow).',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services and waits for their readiness.',
      'Open the printed presentation request deep link with the Wallet Instance on the same device.',
      'Allow the wallet to retrieve and validate the Request Object.',
      'Approve the disclosure of the requested attributes in the wallet.',
      'The runner passes once the Relying Party receives a valid Authorization Response and the wallet follows the redirect_uri back to the Relying Party.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
