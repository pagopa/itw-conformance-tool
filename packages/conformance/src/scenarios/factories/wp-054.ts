import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/** The Authorization Response claim omitted by a given WP_054 variant. */
export type Wp054MissingClaim = 'code' | 'iss' | 'state';

const CLAIM_LABEL: Record<Wp054MissingClaim, string> = {
  code: 'code',
  iss: 'iss',
  state: 'state'
};

function createWp054Scenario(claim: Wp054MissingClaim): ProtocolObservedScenarioDefinition {
  const claimLabel = CLAIM_LABEL[claim];

  return {
    id: `WP_054_MISSING_${claim.toUpperCase()}`,
    title: `Negative Path: Wallet Instance rejects an Authorization Response missing '${claimLabel}'`,
    phase: 'ISSUANCE',
    automationMode: 'interactive-protocol-observed',
    services: ['credentialIssuer', 'federation'],
    stimulus: {
      type: 'credential-offer',
      delivery: ['deep-link', 'qr']
    },
    setup: {
      issuerFault: { type: 'authorization-response-missing-claim', claim }
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
        service: 'credential-issuer',
        correlation: 'allow-uncorrelated-post-start',
        match: { endpoint: '/code/jwt', faultProfileType: 'authorization-response-missing-claim', omittedClaim: claim }
      }
    ],
    forbiddenEvents: ['issuer.token.requested', 'issuer.nonce.requested', 'issuer.credential.requested'],
    timeouts: {
      testerActionMs: 300_000,
      protocolStepMs: 60_000,
      // Long enough for a conforming wallet to receive and evaluate the
      // malformed Authorization Response before we conclude it never
      // continued. Matches WP_046a's window.
      forbiddenObservationMs: 30_000,
      vitestTestMs: 360_000
    },
    verdictRules: [
      { type: 'entry-event-required' },
      { type: 'required-events-in-order' },
      { type: 'no-forbidden-events-after-entry' }
    ],
    instructions: {
      goal: `Verify that the Wallet Instance rejects a Credential Issuer Authorization Response whose '${claimLabel}' parameter is absent.`,
      expectedBehavior: `After opening the credential offer, the wallet must complete the identity/presentation interaction, request the Credential Issuer Authorization Endpoint, and receive an Authorization Response missing '${claimLabel}'. The wallet must detect the malformed response and terminate the issuance flow without exchanging it at the Token Endpoint. Successful conformance is rejection/termination, not issuance.`,
      prerequisites: [
        'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
        'Run the test from the workspace root, where config.ini and the compiled local services are available.',
        'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
      ],
      steps: [
        `Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services, activates the authorization-response-missing-claim fault (claim: '${claimLabel}') on the Credential Issuer, and waits for their readiness.`,
        'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
        'Complete the identity/presentation interaction needed to reach the Authorization Response, the same way as in the happy path scenario.',
        `Do not continue any further step: the expected outcome is that the wallet stops after receiving the Authorization Response with '${claimLabel}' missing.`,
        'The runner will continue automatically after the wallet requests the Authorization Endpoint and the fault application is recorded for /code/jwt, or once the negative-observation window elapses without the wallet requesting the Token Endpoint.'
      ]
    },
    missingRequiredEventPolicy: 'inconclusive'
  };
}

export const wp054MissingCodeScenario = createWp054Scenario('code');

export const wp054Scenarios: ProtocolObservedScenarioDefinition[] = [
  wp054MissingCodeScenario
];
