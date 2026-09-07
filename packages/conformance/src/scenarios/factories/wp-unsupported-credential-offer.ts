import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * Reserved, clearly test-only `credential_configuration_id` injected by the
 * `unsupported-credential-offer` fault. It must never collide with a real
 * Credential Issuer configuration id (see
 * `apps/itw-credential-issuer/src/domain/openid-federation/shared/credential-configurations.ts`),
 * so a conforming Wallet can only find it absent from
 * `credential_configurations_supported`. Exported so the conformance matrix
 * test can assert on it without duplicating the literal.
 */
export const WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID = 'wp_050b_unsupported_credential';

export const wpUnsupportedCredentialOfferScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_Unsupported_Credential_Offer',
  title: 'Negative Path: Wallet Instance rejects a Credential Offer with an unsupported credential_configuration_id',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerFault: {
      type: 'unsupported-credential-offer',
      credentialConfigurationId: WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID
    }
  },
  entryEvent: 'issuer.entity_configuration.requested',
  requiredEvents: [
    {
      event: 'issuer.entity_configuration.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
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
    // Long enough for a conforming wallet to fetch the Credential Issuer
    // metadata (and resolve the trust chain, if needed) and decide the
    // requested credential_configuration_id is unsupported before we
    // conclude it never continued. Matches WP_046a's window.
    forbiddenObservationMs: 30_000,
    vitestTestMs: 360_000
  },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance rejects a Credential Offer whose credential_configuration_ids entry is not published in the Credential Issuer metadata.',
    expectedBehavior:
      'After opening the credential offer, the wallet must request the Credential Issuer Entity Configuration (and resolve the trust chain if needed) to evaluate the offer, discover that the requested credential_configuration_id is absent from credential_configurations_supported, and terminate the issuance flow without sending a Pushed Authorization Request or any later request. Successful conformance is rejection/termination, not issuance.',
    summary: 'Verify rejection of an unsupported credential offer.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Keep the wallet and this command running while the wallet evaluates the offered credential type.',
      'Stop at the wallet rejection screen; the expected outcome is rejection before PAR or later issuance requests.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
