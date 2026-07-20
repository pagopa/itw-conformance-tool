import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wpCiHappyScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_CI_HAPPY',
  title: 'Happy Path: Wallet Instance obtains a credential',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  entryEvent: 'issuer.entity_configuration.requested',
  requiredEvents: ['issuer.entity_configuration.requested', 'federation.fetch.requested'],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    vitestTestMs: 330_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance discovers the Credential Issuer and obtains a credential from it.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration and obtain a credential from the Credential Issuer.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services and waits for their readiness.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
      'Keep the wallet and test process running while the wallet resolves the Credential Issuer federation trust chain.',
      'The runner will continue automatically after the wallet requests the Issuer Entity Configuration and the Trust Anchor subordinate statement.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive',
  preCorrelationEvidence: {
    sequentialInteractiveOnly: true,
    expectedEvents: [
      {
        event: 'issuer.entity_configuration.requested',
        service: 'credential-issuer',
        diagnostics: { endpoint: '/.well-known/openid-federation' }
      },
      {
        event: 'federation.fetch.requested',
        service: 'federation',
        diagnostics: {
          endpoint: '/fetch',
          sub: { endpoint: 'credentialIssuer', match: 'normalized-url' }
        }
      }
    ]
  }
};
