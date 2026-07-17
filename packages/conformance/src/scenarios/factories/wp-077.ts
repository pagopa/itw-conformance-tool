import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp077Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_077',
  title: 'Parse cross-device presentation request QR parameters',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty'],
  stimulus: {
    type: 'presentation-request',
    delivery: ['qr']
  },
  entryEvent: 'rp.request_object.requested',
  requiredEvents: ['rp.request_object.requested', 'rp.presentation_response.received'],
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
    goal: 'Verify that the Wallet Instance scans a cross-device presentation QR Code and extracts client_id, request_uri, state, and request_uri_method.',
    expectedBehavior:
      'After scanning the QR payload, the wallet must parse the authorization request parameters and dereference the request_uri using the advertised request_uri_method.',
    prerequisites: [
      'The wallet app under test is installed and can scan QR payloads for presentation requests.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Relying Party base URL printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services and waits for their readiness.',
      'Scan the printed presentation request QR payload with the Wallet Instance.',
      'Keep the test process running while the wallet interacts with the local Relying Party.',
      'The runner will continue automatically when the wallet requests the request_uri from the Relying Party.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
