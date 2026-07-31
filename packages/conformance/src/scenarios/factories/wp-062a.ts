import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

export const wp062aScenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_062a',
  title: 'Negative Path: Wallet Instance rejects a Digital Credential whose SD-JWT signature is invalid',
  phase: 'ISSUANCE',
  automationMode: 'interactive-protocol-observed',
  services: ['credentialIssuer', 'federation'],
  stimulus: {
    type: 'credential-offer',
    delivery: ['deep-link', 'qr']
  },
  setup: {
    issuerFault: { type: 'edc-invalid-signature' }
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
      label: 'Credential Issuer returned a credential with an invalid SD-JWT signature',
      service: 'credential-issuer',
      correlation: 'allow-uncorrelated-post-start',
      match: {
        endpoint: '/credential',
        faultProfileType: 'edc-invalid-signature',
        mutationTarget: 'jws-signature'
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
    goal: 'Verify that the Wallet Instance rejects a Digital Credential whose SD-JWT signature fails verification, instead of storing it.',
    expectedBehavior:
      'After opening the credential offer, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the Credential Request. The Credential Issuer applies the edc-invalid-signature fault and returns an HTTP 200 application/json immediate response whose issued SD-JWT VC retains valid alg, kid, x5c, trusted public-key material, payload, disclosures, credential type/schema, and holder binding, but whose compact JWS signature segment has been corrupted after serialization. A conformant Wallet Instance must read alg and kid from the SD-JWT header, retrieve the corresponding public key, detect the failed JWS signature verification, report an error to the user, and must not proceed to store the credential. This scenario proves the fault was delivered exactly as configured (protocol-observed evidence only); it cannot itself verify the wallet UI error or its secure storage, which the operator must confirm separately (see the steps below).',
    summary: 'Verify rejection of a credential with an invalid SD-JWT signature.',
    prerequisites: [
      'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
    ],
    steps: [
      'Open the Credential Offer in your Wallet Instance.',
      'Complete identity verification and consent so the wallet sends the Credential Request.',
      'Observe the wallet rejection caused by SD-JWT signature verification failure and keep this command running.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
