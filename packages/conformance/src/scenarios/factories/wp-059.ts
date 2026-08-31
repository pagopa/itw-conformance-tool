import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp059Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_059',
  title: 'Negative Path: Wallet Instance rejects a Credential Response missing the required credentials parameter',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerFault: { type: 'edc-missing-required-claims', parameters: ['credentials'] }
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
    },
    {
      event: 'issuer.fault.applied',
      label: 'Credential Issuer returned a Credential Response without credentials',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/credential',
        faultProfileType: 'edc-missing-required-claims'
      }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 30_000,
    vitestTestMs: 360_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance rejects an immediate Credential Response that omits the required credentials parameter, instead of proceeding to store a Digital Credential.',
    expectedBehavior:
      'After opening the credential offer, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the Credential Request. The Credential Issuer applies the edc-missing-required-claims fault and returns an HTTP 200 application/json immediate response that omits the top-level credentials parameter, leaving every other field unchanged. A conformant Wallet Instance must detect the missing required parameter, report an error to the user, and must not proceed to store any credential. This scenario proves the fault was delivered exactly as configured (protocol-observed evidence only); it cannot itself verify the wallet UI error or its secure storage, which the operator must confirm separately (see the steps below).',
    summary: 'Verify rejection of a Credential Response missing credentials.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Complete identity verification and consent so the wallet sends the Credential Request.',
      'Observe the wallet rejection and keep this command running; the automated verdict checks that the malformed response was delivered.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
