import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wpWalletProviderHappyScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_WALLET_PROVIDER_HAPPY',
  title: 'Happy Path: Wallet Instance obtains a Wallet Instance Attestation',
  phase: 'WALLET_INSTANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['walletProvider', 'federation'],
  stimulus: {
    type: 'manual-instruction',
    text: 'Start Wallet Instance activation against the local Wallet Provider, then complete registration and request a Wallet Instance Attestation.'
  },
  entryEvent: 'wallet_provider.entity_configuration.requested',
  requiredEvents: [
    {
      event: 'wallet_provider.entity_configuration.requested',
      service: 'wallet-provider',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/.well-known/openid-federation' }
    },
    {
      event: 'federation.fetch.requested',
      service: 'federation',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/fetch',
        sub: { endpoint: 'walletProvider', match: 'normalized-url' }
      }
    },
    {
      event: 'wallet_provider.nonce.requested',
      service: 'wallet-provider',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/nonce', method: 'GET', outcome: 'success' }
    },
    {
      event: 'wallet_instance.registration.requested',
      service: 'wallet-provider',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/wallet-instances', method: 'POST', outcome: 'success' }
    },
    {
      event: 'wallet_attestation.requested',
      service: 'wallet-provider',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/wallet-instance-attestation', method: 'POST', outcome: 'success' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    vitestTestMs: 330_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance discovers the Wallet Provider, resolves its Trust Anchor subordinate statement, requests a fresh nonce, registers, and obtains a Wallet Instance Attestation.',
    expectedBehavior:
      'The wallet must request the Wallet Provider Entity Configuration, fetch the Wallet Provider subordinate statement from the Trust Anchor, successfully register through POST /wallet-instances, and then successfully request POST /wallet-instance-attestation.',
    summary: 'Verify Wallet Instance registration and attestation issuance.',
    prerequisites: [
      'The wallet app or client under test can start Wallet Instance activation against a Wallet Provider URL.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The Wallet Instance can reach the local Wallet Provider and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Configure the Wallet Instance to use the local Wallet Provider URL printed by this test.',
      'Start Wallet Instance activation so the wallet contacts the Wallet Provider.',
      'Complete registration and attestation issuance, then keep this command running until the protocol steps are observed.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
