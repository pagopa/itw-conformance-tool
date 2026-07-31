import {
  erasureRequestAccepted,
  presentationTimeouts,
  relyingPartySubordinateStatementRequested,
  rpEntityConfigurationRequested,
  trustAnchorEntityConfigurationRequested
} from './presentation-evidence.js';

import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp116Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_116',
  title: 'Happy Path: Wallet Instance discovers the Relying Party erasure endpoint and sends an Erasure Request',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty', 'federation'],
  stimulus: {
    type: 'manual-instruction',
    text: 'Open the Wallet Instance attribute-erasure flow, select the local Relying Party, and confirm the action that sends the Erasure Request.'
  },
  entryEvent: 'rp.metadata.requested',
  requiredEvents: [
    rpEntityConfigurationRequested,
    trustAnchorEntityConfigurationRequested,
    relyingPartySubordinateStatementRequested,
    erasureRequestAccepted
  ],
  timeouts: { ...presentationTimeouts, vitestTestMs: 420_000 },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance resolves the selected local Relying Party through OpenID Federation, discovers metadata.openid_credential_verifier.erasure_endpoint, and sends a valid GET Erasure Request to that endpoint.',
    expectedBehavior:
      'After the tester selects the local Relying Party from the wallet erasure flow, the wallet retrieves the Relying Party Entity Configuration, validates its Trust Chain through the Trust Anchor, reads the HTTPS erasure_endpoint claim, and sends GET /erasure to the published Relying Party endpoint. This scenario does not validate user authentication, persistent attribute deletion, callback handling, or final erasure notification.',
    prerequisites: [
      'The wallet has already presented an identifying attribute, such as tax_id_code, to the local Relying Party and still stores the related transaction or relying-party relationship.',
      'When running only WP_116, prepare that prior presentation before starting this scenario; in a full presentation run, the preceding happy path can create it.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The Wallet Instance can reach the local Relying Party and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services and waits for their readiness.',
      'Open the wallet function for deleting attributes or removing relying-party access.',
      'Select the local Relying Party printed by this test.',
      'Confirm the action needed for the wallet to send the Erasure Request.',
      'The runner passes only after the Relying Party Entity Configuration, Trust Anchor Entity Configuration, subordinate statement, and accepted GET /erasure request are observed in order.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
