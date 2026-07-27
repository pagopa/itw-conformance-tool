import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wpNotificationScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_Notification',
  title: 'Wallet Instance sends a Notification Request to the Notification Endpoint after issuance',
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
    },
    {
      event: 'issuer.credential.issued',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential' }
    },
    {
      event: 'issuer.notification.received',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/notification' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    // Longer than the happy-path protocol step budget so the wallet has time
    // to accept/store the credential and send the Notification Request
    // after the Credential Response, before the runner gives up.
    vitestTestMs: 420_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance sends a Notification Request to the Notification Endpoint after receiving a Credential Response containing notification_id.',
    expectedBehavior:
      'After opening the credential offer, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the Credential Request and receive an immediate HTTP 200 Credential Response that includes a notification_id. The wallet must keep running after storing (or rejecting) the credential and send an HTTP POST Notification Request to the Notification Endpoint with a JSON body containing the same notification_id and one of the three defined event values (credential_accepted, credential_deleted, credential_failure), optionally with an event_description. This scenario accepts any of the three event values: it does not require credential_accepted specifically, only that the Notification Request itself is well-formed and correlated to the Credential Response.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must support the IT-Wallet Notification Endpoint and send a Notification Request after completing (or failing) credential storage.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services and waits for their readiness.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
      'Complete the identity verification / consent step in the (mock) Identity Provider so the wallet receives the authorization code, automatically exchanges it at the Token endpoint, obtains a fresh nonce, and sends the Credential Request.',
      'Keep the wallet and test process active after the Credential Response so the wallet can complete credential storage/consent handling and send the Notification Request to the Notification Endpoint.',
      'The runner will continue automatically after the Credential Issuer observes a valid Notification Request.'
    ]
  },
  // Unlike the happy-path scenario, a Wallet Instance that completes
  // issuance but never sends the Notification Request must FAIL this
  // scenario, not be reported as INCONCLUSIVE: entering the scenario (the
  // entry event) already proves the wallet engaged with the flow, so a
  // missing Notification Request is a genuine conformance gap.
  missingRequiredEventPolicy: 'fail'
};
