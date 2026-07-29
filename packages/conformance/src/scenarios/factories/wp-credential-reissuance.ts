import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const WP_CREDENTIAL_REISSUANCE_EXPIRED_TOKENS = 'WP_CREDENTIAL_REISSUANCE_EXPIRED_TOKENS';
export const WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS = 5;
export const WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS = 300;
export const WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS = 86_400;
export const WP_CREDENTIAL_REISSUANCE_STATUS_INDEX = 1;
export const WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS = 0x03;

const initialStatusList = [0, 0, 0, 0, 0];
const updatedStatusList = [...initialStatusList];
updatedStatusList[WP_CREDENTIAL_REISSUANCE_STATUS_INDEX] = WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS;

export const wpCredentialReissuanceScenario: ProtocolObservedScenarioDefinition = {
  id: WP_CREDENTIAL_REISSUANCE_EXPIRED_TOKENS,
  title: 'Expired-token credential re-issuance after Status List UPDATE',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    credentialConfigurationId: 'dc_sd_jwt_EuropeanDisabilityCard',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerConfig: {
      batchIssuanceByDeferred: false,
      accessTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS,
      refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS,
      statusList: {
        bits: 4,
        values: initialStatusList
      }
    }
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
      match: { endpoint: '/credential', responseKind: 'immediate' }
    },
    {
      event: 'issuer.status_list.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/statuslist/1', bits: 4, statusValue: WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS }
    },
    {
      event: 'issuer.token.failed',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/token', grantType: 'refresh_token', error: 'invalid_grant' }
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
      match: { endpoint: '/credential', responseKind: 'immediate' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 120_000,
    vitestTestMs: 720_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that a Wallet Instance detects a Status List UPDATE after the original token pair expires, fails refresh-token reuse, and completes a new authorization-code issuance flow for the updated credential.',
    expectedBehavior:
      'After the first credential is issued, keep the wallet and test runner active. The test waits until the original Access Token and Refresh Token have expired, switches the credential status index to UPDATE, and waits for the wallet to request the Status List. The wallet must then attempt the expired Refresh Token exchange, receive invalid_grant, start a new PAR and Authorization flow, complete User authorization/authentication again, exchange a new authorization code, obtain a fresh nonce, and retrieve a newly issued DPoP-bound Digital Credential.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must check Status List Tokens and support restarting issuance after a full Access Token and Refresh Token expiry.',
      'The wallet must send the failed refresh_token exchange for this conformance scenario; local-only refresh short-circuiting is not accepted for WP_067 evidence.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services with short initial token lifetimes and nominal status index 1.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance and complete the first issuance.',
      'Keep the wallet and test process active after the first credential. The test will wait for the original token pair to expire and then switch status index 1 to UPDATE.',
      'When the tool announces the status transition, reopen or foreground the wallet so it checks the Status List and continues re-issuance.',
      'Complete the second authorization/authentication interaction. The runner continues after observing the failed refresh, second PAR/Authorization/code Token exchange, second Nonce request, DPoP Credential Request, and updated credential issuance.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};

export const wpCredentialReissuanceUpdatedIssuerConfig = {
  batchIssuanceByDeferred: false,
  accessTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS,
  statusList: {
    bits: 4,
    values: updatedStatusList
  }
} as const;
