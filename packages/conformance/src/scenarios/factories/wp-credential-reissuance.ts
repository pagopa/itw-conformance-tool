import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const WP_CREDENTIAL_REISSUANCE_EXPIRED_TOKENS = 'WP_CREDENTIAL_REISSUANCE_EXPIRED_TOKENS';
export const WP_CREDENTIAL_REISSUANCE_REFRESH_ACCESS_TOKEN = 'WP_CREDENTIAL_REISSUANCE_REFRESH_ACCESS_TOKEN';
export const WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN = 'WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN';
export const WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS = 5;
export const WP_CREDENTIAL_REISSUANCE_INITIAL_REFRESH_TOKEN_TTL_SECONDS = 900;
export const WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN_TTL_SECONDS = 900;
export const WP_CREDENTIAL_REISSUANCE_INITIAL_STATUS_LIST_TTL_SECONDS = 10;
export const WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS = 300;
export const WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS = 86_400;
export const WP_CREDENTIAL_REISSUANCE_STATUS_INDEX = 1;
export const WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS = 0x03;

const initialStatusList = [0, 0, 0, 0, 0];
const updatedStatusList = [...initialStatusList];
updatedStatusList[WP_CREDENTIAL_REISSUANCE_STATUS_INDEX] = WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS;

const initialIssuanceRequiredEvents: NonNullable<ProtocolObservedScenarioDefinition['requiredEvents']> = [
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
    match: { endpoint: '/token', grantType: 'authorization_code' }
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
];

const updatedStatusListRequiredEvent = {
  event: 'issuer.status_list.requested',
  service: 'credential-issuer',
  correlation: 'allow-uncorrelated-post-start',
  match: { endpoint: '/statuslist/1', bits: 4, statusValue: WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS }
} satisfies NonNullable<ProtocolObservedScenarioDefinition['requiredEvents']>[number];

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
    ...initialIssuanceRequiredEvents,
    updatedStatusListRequiredEvent,
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

export const wpCredentialReissuanceRefreshAccessTokenScenario: ProtocolObservedScenarioDefinition = {
  id: WP_CREDENTIAL_REISSUANCE_REFRESH_ACCESS_TOKEN,
  title: 'Refresh-token credential re-issuance after Status List UPDATE',
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
      refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_INITIAL_REFRESH_TOKEN_TTL_SECONDS,
      statusList: {
        bits: 4,
        ttlSeconds: WP_CREDENTIAL_REISSUANCE_INITIAL_STATUS_LIST_TTL_SECONDS,
        values: initialStatusList
      }
    }
  },
  entryEvent: 'issuer.entity_configuration.requested',
  requiredEvents: [
    ...initialIssuanceRequiredEvents,
    updatedStatusListRequiredEvent,
    {
      event: 'issuer.token.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/token', grantType: 'refresh_token' }
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
    goal: 'Verify that a Wallet Instance detects a Status List UPDATE after the original Access Token expires and uses the still-valid Refresh Token to obtain a new DPoP-bound Access Token.',
    expectedBehavior:
      'After the first credential is issued, keep the wallet and test runner active. The test waits until the original Access Token and any nominal Status List Token cache have expired, switches credential status index 1 to UPDATE, and asks you to reopen or foreground the wallet. The wallet must request the updated Status List, perform one successful refresh_token exchange with the originally issued Refresh Token, obtain a fresh nonce, and retrieve a newly issued DPoP-bound Digital Credential with the refreshed Access Token. It must not start a second PAR or Authorization flow during this re-issuance window.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must check Status List Tokens and support automatic Refresh Token flow for credential re-issuance.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services with a short-lived Access Token, a long-lived Refresh Token, and nominal status index 1.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance and complete the first issuance.',
      'Keep the wallet and test process active after the first credential. The test waits until the original Access Token and any observed nominal Status List Token have expired, then switches status index 1 to UPDATE.',
      'When the tool announces the status transition, reopen or foreground the wallet so it checks the Status List and continues automatic re-issuance.',
      'Do not start a new issuance flow manually. The runner continues after observing the updated Status List, successful Refresh Token exchange, second Nonce request, second DPoP Credential Request, and updated credential issuance.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};

export const wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig = {
  batchIssuanceByDeferred: false,
  accessTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS,
  statusList: {
    bits: 4,
    values: updatedStatusList
  }
} as const;

export const wpCredentialReissuanceValidAccessTokenScenario: ProtocolObservedScenarioDefinition = {
  id: WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN,
  title: 'Valid-token credential re-issuance after Status List UPDATE',
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
      accessTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS,
      statusList: {
        bits: 4,
        ttlSeconds: WP_CREDENTIAL_REISSUANCE_INITIAL_STATUS_LIST_TTL_SECONDS,
        values: initialStatusList
      }
    }
  },
  entryEvent: 'issuer.entity_configuration.requested',
  requiredEvents: [
    ...initialIssuanceRequiredEvents,
    updatedStatusListRequiredEvent,
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
    goal: 'Verify that a Wallet Instance detects a Status List UPDATE and re-issues the credential with the still-valid associated Access Token.',
    expectedBehavior:
      'After the first credential is issued, keep the wallet and test runner active. The test briefly waits for any nominal Status List Token cache to expire, switches credential status index 1 to UPDATE, and asks you to reopen or foreground the wallet. The wallet must request the updated Status List, obtain a fresh nonce, and retrieve a newly issued DPoP-bound Digital Credential with the original still-valid Access Token. It must not use a Refresh Token flow or start a new PAR/Authorization flow during re-issuance.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must check Status List Tokens and support automatic re-issuance while the original Access Token remains valid.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services with a long-lived Access Token and a short nominal Status List lifetime.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance and complete the first issuance.',
      'Keep the wallet and test process active after the first credential. The test will switch status index 1 to UPDATE while the original Access Token remains valid.',
      'When the tool announces the status transition, reopen or foreground the wallet so it checks the Status List and continues re-issuance.',
      'Do not start a new issuance flow manually. The runner continues after observing the updated Status List, second Nonce request, second DPoP Credential Request, and updated credential issuance.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};

export const wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig = {
  batchIssuanceByDeferred: false,
  accessTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlSeconds: WP_CREDENTIAL_REISSUANCE_REFRESHED_REFRESH_TOKEN_TTL_SECONDS,
  statusList: {
    bits: 4,
    values: updatedStatusList
  }
} as const;
