import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp057Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_057',
  title: 'Multiple credentials: Wallet Instance sends a separate Credential Request for each offered credential',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    credentialConfigurationIds: ['dc_sd_jwt_EuropeanDisabilityCard', 'org.iso.18013.5.1.mDL'],
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
    // Declared twice: the wallet must send one ordinary Credential Request
    // per offered credential (not a single batch-style request), so each
    // Credential Request/issuance pair is a distinct required occurrence.
    // The cardinality-aware verdict engine matches each declaration to a
    // distinct observed event instead of resolving both to the same first
    // occurrence.
    {
      event: 'issuer.credential.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    },
    {
      event: 'issuer.credential.issued',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    },
    {
      event: 'issuer.credential.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    },
    {
      event: 'issuer.credential.issued',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    vitestTestMs: 600_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that, when offered multiple Digital Credentials in a single Credential Offer, the Wallet Instance sends a separate and correctly formatted Credential Request for each Digital Credential it intends to accept, rather than combining them into a single request.',
    expectedBehavior:
      'After opening the credential offer with two distinct credential_configuration_ids, the wallet must complete the normal issuance flow through Entity Configuration, Federation Fetch, PAR, Authorization, Token and Nonce, then accept both offered credentials by sending two separate DPoP-authenticated Credential Requests to the Credential endpoint, each carrying exactly one credential_identifier and exactly one holder-binding proof JWT. The Credential Issuer must independently validate and issue each request, resulting in two issuer.credential.issued responses that together cover both offered credential identifiers.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must be able to accept both offered credential types from a single Credential Offer.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services and waits for their readiness.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
      'Complete the identity verification / consent step in the (mock) Identity Provider so the wallet receives the authorization code, exchanges it at the Token endpoint and obtains a fresh nonce.',
      'Accept both offered credentials in the Wallet Instance and keep the wallet and test process running until it has sent a separate Credential Request for each one and received both credentials.',
      'The runner will continue automatically after the wallet sends and receives a response for two separate Credential Requests, one for each offered credential.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
