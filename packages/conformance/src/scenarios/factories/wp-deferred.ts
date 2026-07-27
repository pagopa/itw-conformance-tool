import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wpDeferredScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_Deferred',
  title:
    'Deferred batch issuance: Wallet Instance sends a complete batch request and waits for the advertised interval',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    credentialConfigurationIds: ['dc_sd_jwt_EuropeanDisabilityCard', 'dc_sd_jwt_EuropeanDisabilityCard'],
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerConfig: {
      batchIssuanceByDeferred: true
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
      event: 'issuer.credential.deferred',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/credential', responseKind: 'deferred' }
    },
    {
      event: 'issuer.deferred_credential.requested',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/deferred' }
    },
    {
      event: 'issuer.deferred_credential.issued',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: { endpoint: '/deferred' }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 120_000,
    vitestTestMs: 480_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance builds a complete batch Credential Request using the Issuer metadata batch_size, distinct holder-binding proof keys and the Nonce Endpoint c_nonce, then treats the HTTP 202 Credential Response as deferred issuance and waits for the advertised interval before calling the Deferred Credential Endpoint.',
    expectedBehavior:
      'After opening the credential offer with two credential types, the wallet must complete the normal issuance flow through Entity Configuration, Federation Fetch, PAR, Authorization, Token and Nonce, read openid_credential_issuer.batch_credential_issuance.batch_size from the Issuer metadata, then send a DPoP-authenticated Credential Request for one of the offered credential identifiers with exactly N holder-binding proof JWTs, where N equals the published batch_size. Each proof JWT must use a public asymmetric JWK that is distinct from every other proof key and from the Credential Request DPoP key, and each proof must carry the same c_nonce obtained from the Nonce Endpoint. The Credential Issuer enables deferred batch issuance only for this scenario and returns HTTP 202 with transaction_id and interval and no credentials. The wallet must keep running, wait for the advertised interval, call POST /deferred with the same transaction_id and valid DPoP-bound access-token authentication, then receive the deferred credentials.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'The wallet must support the Issuer metadata batch_size for batch credential issuance and generate exactly that many holder-binding proof JWTs.',
      'The wallet must generate distinct holder-binding proof keys for the batch and use the fresh c_nonce from the Nonce Endpoint in every proof JWT.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.',
      'The automated verdict observes protocol traffic and timing, not the wallet internal state machine.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services and enables deferred batch issuance only for this scenario.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance.',
      'Complete the identity verification / consent step in the (mock) Identity Provider so the wallet receives the authorization code, exchanges it at the Token endpoint, obtains a fresh nonce and sends the batch Credential Request.',
      'Keep the wallet and test process active after the HTTP 202 response so the wallet can wait for the advertised interval and automatically call the Deferred Endpoint.',
      'The runner will continue automatically after the Credential Issuer observes the deferred response, the Deferred Credential Request and the successful deferred credential response.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
