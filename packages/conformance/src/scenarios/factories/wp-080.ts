import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp080Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_080',
  title: 'Evaluate Relying Party Trust Mark',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['federation', 'relyingParty'],
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
    goal: 'Verify that the Wallet Instance validates the Trust Mark in the Relying Party Entity Configuration before continuing a presentation flow.',
    expectedBehavior:
      'The wallet retrieves the Relying Party Entity Configuration and its Trust Chain, verifies the Trust Mark signature, validity period, subject, and authorized issuer policy, then continues the presentation flow.',
    prerequisites: [
      'The wallet app under test is installed and can scan QR payloads for presentation requests.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services and waits for their readiness.',
      'Scan the printed presentation request QR payload with the Wallet Instance.',
      'Allow the wallet to retrieve the Relying Party Entity Configuration and evaluate its Trust Mark against the Trust Anchor policy.',
      'Complete the presentation approval in the wallet. The runner will pass when the Relying Party receives and accepts the presentation response.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
