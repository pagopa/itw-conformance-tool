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
  requiredEvents: [
    {
      event: 'issuer.entity_configuration.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
    },
    {
      event: 'federation.fetch.requested',
      service: 'federation',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/fetch',
        sub: { endpoint: 'credentialIssuer', match: 'normalized-url' }
      }
    },
    {
      event: 'issuer.par.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/as/par' }
    },
    {
      event: 'issuer.authorization.requested',
      service: 'credential-issuer'
    },
    {
      event: 'issuer.token.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/token' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    vitestTestMs: 330_000
  },
  verdictRules: [{ type: 'entry-event-required' }],
  instructions: {
    goal: 'Verify that the Wallet Instance discovers the Credential Issuer and successfully completes the Authorization Code Flow through PAR, Authorization, and Token exchange.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration, resolve the Trust Anchor subordinate statement, successfully push an Authorization Request to the Credential Issuer PAR endpoint, request the Credential Issuer Authorization Endpoint using the received request_uri and client_id, complete the identity verification/consent step with the (mock) Identity Provider, and exchange the resulting authorization code at the Credential Issuer Token endpoint.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services and waits for their readiness.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
      'Keep the wallet and test process running while the wallet resolves the Credential Issuer federation trust chain.',
      'Complete the identity verification / consent step in the (mock) Identity Provider so the wallet receives the authorization code and automatically exchanges it at the Token endpoint.',
      'The runner will continue automatically after the wallet requests the Issuer Entity Configuration, the Trust Anchor subordinate statement, pushes the Authorization Request to the PAR endpoint, requests the Authorization Endpoint with the received request_uri and client_id, and exchanges the authorization code at the Token endpoint.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
