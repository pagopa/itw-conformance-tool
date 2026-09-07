import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const WP_050A_METADATA_POLICY_CREDENTIAL_CONFIGURATION_ID = 'mso_mdoc_PersonIdentificationData';

export const wp050aMetadataPolicyScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_050A_METADATA_POLICY',
  title: 'Negative Path: Wallet Instance rejects a Credential Issuer not authorized by metadata policy',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    credentialConfigurationId: WP_050A_METADATA_POLICY_CREDENTIAL_CONFIGURATION_ID,
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
        sub: { match: 'normalized-url', endpoint: 'credentialIssuer' }
      }
    }
  ],
  forbiddenEvents: [
    'issuer.par.requested',
    'issuer.authorization.requested',
    'issuer.token.requested',
    'issuer.nonce.requested',
    'issuer.credential.requested'
  ],
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
    goal: 'Verify that the Wallet Instance applies the Trust Anchor metadata policy and rejects a Credential Issuer that is not authorized to issue the requested Digital Credential.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration, fetch the Credential Issuer Subordinate Statement from the Trust Anchor, apply the metadata policy, and terminate the issuance flow because the requested credential_configuration_id is not authorized by the resolved metadata. Successful conformance is termination after trust evaluation, not a specific wallet UI message.',
    summary: 'Verify rejection of a credential type not authorized by Trust Anchor policy.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.',
      'Use a fresh trust-evaluation run or clear the wallet federation cache if the wallet caches subordinate statements.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Keep the wallet and this command running while the wallet resolves the Credential Issuer through the Trust Anchor.',
      'Stop at the wallet rejection screen; the expected outcome is rejection after metadata policy evaluation.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
