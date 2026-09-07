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
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/authorize' }
    },
    {
      event: 'issuer.token.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/token' }
    },
    {
      event: 'issuer.nonce.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/nonce' }
    },
    {
      event: 'issuer.credential.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    vitestTestMs: 330_000
  },
  verdictRules: [{ type: 'entry-event-required' }],
  instructions: {
    goal: 'Verify that the Wallet Instance discovers the Credential Issuer and successfully completes the Authorization Code Flow through PAR, Authorization, Token, Nonce, and Credential requests.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration, resolve the Trust Anchor subordinate statement, successfully push an Authorization Request to the Credential Issuer PAR endpoint, request the Credential Issuer Authorization Endpoint using the received request_uri and client_id, complete the identity verification/consent step with the (mock) Identity Provider, exchange the resulting authorization code at the Credential Issuer Token endpoint, obtain a fresh c_nonce from the Nonce endpoint, and automatically complete issuance at the Credential endpoint.',
    summary: 'Verify a complete credential issuance flow.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer links or scan credential offer QR codes.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Complete identity verification and consent in the wallet.',
      'Keep the wallet and this command running until the scenario completes.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
