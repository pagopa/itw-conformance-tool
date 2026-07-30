import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp062bScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_062b',
  title: 'Negative Path: Wallet Instance rejects an mdoc-CBOR credential whose MSO COSE signature is invalid',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr'],
    credentialConfigurationId: 'org.iso.18013.5.1.mDL'
  },
  setup: {
    issuerFault: { type: 'mdl-invalid-signature' }
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
      event: 'issuer.fault.applied',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/credential',
        faultProfileType: 'mdl-invalid-signature',
        mutationTarget: 'issuerAuth.cose-signature'
      }
    }
  ],
  timeouts: {
    testerActionMs: 300_000,
    protocolStepMs: 30_000,
    vitestTestMs: 360_000
  },
  verdictRules: [{ type: 'entry-event-required' }, { type: 'required-events-in-order' }],
  instructions: {
    goal: 'Verify that the Wallet Instance rejects an mDL mdoc-CBOR credential whose MSO COSE signature fails verification, instead of storing it.',
    expectedBehavior:
      'After opening the credential offer for org.iso.18013.5.1.mDL, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the mDL Credential Request. The Credential Issuer applies the mdl-invalid-signature fault and returns an HTTP 200 application/json immediate response that is otherwise valid and contains an mdoc-CBOR credential whose issuerAuth remains a well-formed COSE_Sign1 with preserved alg, kid/x5chain, MSO payload, namespaces, credential data, digest data, validity, and holder binding, but whose COSE signature bytes have been corrupted after serialization. A conformant Wallet Instance must resolve the issuer key from the preserved kid or x5chain, detect the failed MSO COSE signature verification, report an error to the user, and must not store the mDL. This scenario proves the controlled fault was delivered (protocol-observed evidence only); it cannot itself verify the wallet UI error or secure storage, which the operator must confirm separately.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test issuance. The CLI starts the required Trust Anchor and Credential Issuer services, activates the mdl-invalid-signature fault on the Credential Issuer, and waits for their readiness.',
      'Open the printed credential offer deep link or scan the QR payload with the Wallet Instance; the offer requests the mDL credential configuration org.iso.18013.5.1.mDL.',
      'Complete the identity verification / consent step in the (mock) Identity Provider so the wallet receives the authorization code, automatically exchanges it at the Token endpoint, obtains a fresh nonce, and sends the mDL Credential Request.',
      'Observe the Wallet Instance: the expected outcome is that it reports an error caused by MSO COSE signature verification failure and does not add the mDL to secure storage. Record this observation yourself; the automated verdict below only proves the defective credential was delivered, not that the wallet rejected it.',
      'The runner will continue automatically after the wallet requests the Credential endpoint and the fault application is recorded.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
