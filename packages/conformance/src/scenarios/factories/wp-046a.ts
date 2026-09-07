import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp046aScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_046a',
  title: 'Negative Path: Wallet Instance rejects an invalid Trust Anchor',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerFault: { type: 'invalid-trust-anchor' }
  },
  entryEvent: 'issuer.entity_configuration.requested',
  requiredEvents: [
    {
      event: 'issuer.entity_configuration.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
    },
    {
      event: 'issuer.fault.applied',
      label: 'Credential Issuer served invalid Trust Anchor metadata',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation', faultProfileType: 'invalid-trust-anchor' }
    }
  ],
  forbiddenEvents: ['federation.fetch.requested', 'issuer.par.requested'],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    // Long enough for a conforming wallet to fetch, parse, and reject the
    // mutated Entity Configuration before we conclude it never continued.
    forbiddenObservationMs: 30_000,
    vitestTestMs: 360_000
  },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance rejects a Credential Issuer whose Entity Configuration authority_hints point outside the expected Trust Anchor.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration, discover that its authority_hints do not include the expected Trust Anchor, and terminate the issuance flow without resolving the Trust Anchor subordinate statement or continuing to the Credential Issuer PAR endpoint. Successful conformance is rejection/termination, not issuance.',
    summary: 'Verify rejection of a Credential Issuer with an invalid Trust Anchor.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Keep the wallet and this command running while the wallet inspects the Credential Issuer metadata.',
      'Stop at the wallet rejection screen; the expected outcome is rejection before Trust Anchor resolution or PAR.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
