import {
  authorizationResponseReceived,
  presentationEntryEvent,
  presentationTimeouts,
  requestObjectRequested,
  vpTokenValidationSucceeded
} from './presentation-evidence.js';

import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * Happy-path OpenID4VP remote presentation flow, cross-device with a POST
 * Request Object retrieval.
 *
 * This is the companion of `wpRpHappyScenario`: it covers the Test Matrix cases
 * the same-device/GET flow cannot cover in the same run, because each pair is
 * mutually exclusive. The engagement is delivered as a QR payload for a
 * cross-device flow (WP_077 rather than WP_076) and advertises
 * `request_uri_method=post`, so the wallet retrieves the Request Object with an
 * HTTP POST carrying `wallet_metadata` and `wallet_nonce` (WP_083, and the
 * WP_083a/b/c checks on that body).
 *
 * A cross-device flow ends at the Authorization Response: the verifier resumes
 * on the initiating device by polling its own session status, so no user-agent
 * redirect is expected here — WP_094 stays with the same-device flow.
 *
 * Like `wpRpHappyScenario`, the engagement uses the nominal `x509_hash` trust
 * model, so no federation call is expected: everything the wallet needs to
 * verify the Request Object and encrypt the response travels in the Request
 * Object itself.
 */
export const wpRpHappyPostScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_RP_HAPPY_POST',
  title: 'Happy Path: Wallet Instance retrieves the Request Object with a POST and presents a credential',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty', 'federation'],
  stimulus: {
    // WP_077 (QR / cross-device) is chosen over the mutually exclusive WP_076,
    // and `post` over the mutually exclusive WP_082 GET retrieval.
    type: 'presentation-request',
    clientIdPrefix: 'x509_hash',
    delivery: ['qr'],
    requestUriMethod: 'post'
  },
  // The Request Object retrieval is the first call an `x509_hash` wallet makes.
  entryEvent: presentationEntryEvent('x509_hash'),
  requiredEvents: [
    // WP_083 / WP_083a / WP_083b / WP_083c: the engagement advertises
    // request_uri_method=post, so the wallet must POST its metadata and a fresh
    // nonce to the request_uri endpoint.
    requestObjectRequested('POST', 'x509_hash'),
    authorizationResponseReceived,
    vpTokenValidationSucceeded
  ],
  forbiddenEvents: ['vp_token.validation.failed', 'rp.presentation_error.received'],
  timeouts: { ...presentationTimeouts, forbiddenObservationMs: 5_000, vitestTestMs: 330_000 },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance obtains the presentation request from a QR code, retrieves the signed Request Object with an HTTP POST carrying wallet_metadata and a fresh wallet_nonce, and completes the presentation with an encrypted Authorization Response.',
    expectedBehavior:
      'After scanning the QR payload, the wallet resolves the Relying Party Entity Configuration and Trust Chain from the Trust Anchor, sends an application/x-www-form-urlencoded HTTP POST with wallet_metadata and wallet_nonce to the request_uri endpoint, validates the returned Request Object (which echoes the wallet_nonce), and posts an encrypted Authorization Response with a vp_token to the response_uri.',
    summary: 'Verify credential presentation with QR engagement and POST Request Object retrieval.',
    prerequisites: [
      'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
      'The wallet supports request_uri_method=post; a wallet that always retrieves the Request Object over GET cannot satisfy this scenario.',
      'A second device can scan the presentation request QR payload (cross-device flow).',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Scan the presentation request QR payload with the Wallet Instance.',
      'Allow the wallet to resolve the Relying Party federation trust chain and retrieve the Request Object over POST.',
      'Approve the requested disclosure in the wallet.',
      'Keep the wallet and this command running until the scenario completes.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
