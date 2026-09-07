import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp054aInvalidStateScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_054A_INVALID_STATE',
  title: 'Negative Path: Wallet Instance rejects an Authorization Response with mismatched state',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerFault: { type: 'authorization-response-invalid-state' }
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
      event: 'issuer.fault.applied',
      label: 'Credential Issuer returned an Authorization Response with a mismatched state',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/code/jwt', faultProfileType: 'authorization-response-invalid-state', mutatedClaim: 'state' }
    }
  ],
  forbiddenEvents: ['issuer.token.requested', 'issuer.nonce.requested', 'issuer.credential.requested'],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    forbiddenObservationMs: 30_000,
    vitestTestMs: 360_000
  },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance rejects a Credential Issuer Authorization Response whose state differs from the Request Object state.',
    expectedBehavior:
      'After opening the credential offer, the wallet must complete the identity/presentation interaction, request the Credential Issuer Authorization Endpoint, and receive an Authorization Response whose state is present but different from the Request Object state. The wallet must detect the mismatch and terminate the issuance flow without exchanging the authorization code at the Token Endpoint. Successful conformance is rejection/termination, not credential issuance or a specific UI message.',
    summary: 'Verify rejection of an Authorization Response with mismatched state.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Complete identity verification and consent until the wallet receives the Authorization Response.',
      'Stop at the wallet rejection screen; the expected outcome is rejection of the mismatched state.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
