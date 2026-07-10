import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp046Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_046',
  title: 'Discover Credential Issuer dynamically from federation metadata',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['qr', 'deep-link']
  },
  entryEvent: 'issuer.entity_configuration.requested',
  setup: {
    issuer: {
      federationMetadataMode: 'current'
    }
  },
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 60_000,
    forbiddenObservationMs: 5_000,
    vitestTestMs: 330_000
  },
  verdictRules: [{ type: 'entry-event-required' }],
  instructions: {
    goal: 'Verify that the Wallet Instance dynamically discovers the Credential Issuer configuration through OpenID Federation metadata.',
    expectedBehavior:
      'After opening the credential offer, the wallet must call the local Credential Issuer Federation API endpoint /.well-known/openid-federation and use the returned current issuer metadata/configuration before continuing the issuance flow.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan QR payloads.',
      'The local Credential Issuer and other selected local services are already running before launching the test matrix.',
      'The device running the wallet can reach the advertised local Credential Issuer base URL printed by this test.',
      'If the wallet runs on a physical device, expose this machine on the same network or through a tunnel and set ITW_CT_ADVERTISED_HOST or ITW_CT_ISSUER_ADVERTISED_BASE_URL accordingly.'
    ],
    steps: [
      'Start this scenario through the conformance test matrix command after the local services are already running: nx run itw-conformance-cli:run --args="test".',
      'Open the printed credential offer deep link, or scan/copy the printed QR payload with the Wallet Instance.',
      'Keep the test process running while the wallet interacts with the local Credential Issuer.',
      'Proceed in the wallet until it starts issuer discovery; the runner will continue automatically when /.well-known/openid-federation is requested.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
