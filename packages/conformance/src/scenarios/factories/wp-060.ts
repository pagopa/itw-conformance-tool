import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/** The WP_060 Digital Credential claims defect exercised by a given scenario variant. */
export type Wp060Variant = 'type-mismatch' | 'schema-invalid';

const VARIANT_LABEL: Record<Wp060Variant, string> = {
  'type-mismatch': 'a type mismatch on the issued Digital Credential',
  'schema-invalid': "a missing required claim ('issuing_country') on the issued Digital Credential"
};

const VARIANT_ID_SUFFIX: Record<Wp060Variant, string> = {
  'type-mismatch': 'TYPE_MISMATCH',
  'schema-invalid': 'SCHEMA_INVALID'
};

function createWp060Scenario(variant: Wp060Variant): ProtocolObservedScenarioDefinition {
  const defectLabel = VARIANT_LABEL[variant];

  return {
    id: `WP_060_${VARIANT_ID_SUFFIX[variant]}`,
    title: `Negative Path: Wallet Instance rejects a Digital Credential with ${defectLabel}`,
    phase: 'ISSUANCE',
    automationMode: 'interactive-protocol-observed',
    services: ['credentialIssuer', 'federation'],
    stimulus: {
      type: 'credential-offer',
      delivery: ['deep-link', 'qr']
    },
    setup: {
      issuerFault: { type: 'digital-credential-claims-invalid', variant }
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
        label: `Credential Issuer returned a credential with ${defectLabel}`,
        service: 'credential-issuer',
        correlation: 'allow-uncorrelated-post-start',
        match: {
          endpoint: '/credential',
          faultProfileType: 'digital-credential-claims-invalid',
          variant
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
      goal: `Verify that the Wallet Instance rejects a Digital Credential exhibiting ${defectLabel}, instead of storing it.`,
      expectedBehavior:
        variant === 'type-mismatch'
          ? "After opening the credential offer, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the Credential Request. The Credential Issuer applies the digital-credential-claims-invalid fault (type-mismatch variant) and returns an HTTP 200 application/json immediate response whose issued SD-JWT VC is validly signed but carries a 'vct' that does not match the Digital Credential type requested/published for the credential configuration, while every other claim remains nominal. A conformant Wallet Instance must detect that the credential's type does not match what was requested, report an error to the user, and must not proceed to store the credential. This scenario proves the fault was delivered exactly as configured (protocol-observed evidence only); it cannot itself verify the wallet UI error or its secure storage, which the operator must confirm separately (see the steps below)."
          : "After opening the credential offer, the wallet must complete the Authorization Code Flow through PAR, Authorization, Token, and Nonce exactly as in the happy path, then send the Credential Request. The Credential Issuer applies the digital-credential-claims-invalid fault (schema-invalid variant) and returns an HTTP 200 application/json immediate response whose issued SD-JWT VC is validly signed and keeps the nominal 'vct', but omits the required, non-selectively-disclosable 'issuing_country' Digital Credential Data Model claim. A conformant Wallet Instance must detect the schema violation, report an error to the user, and must not proceed to store the credential. This scenario proves the fault was delivered exactly as configured (protocol-observed evidence only); it cannot itself verify the wallet UI error or its secure storage, which the operator must confirm separately (see the steps below).",
      summary: `Verify rejection of a credential with ${defectLabel}.`,
      prerequisites: [
        'The wallet app under test is installed and can open credential offer deep links or scan credential offer QR payloads.',
        'Run the test from the workspace root, where config.ini and the compiled local services are available.',
        'The device running the wallet can reach the local Credential Issuer and Trust Anchor URLs printed by this test.'
      ],
      steps: [
        'Open the Credential Offer in your Wallet Instance.',
        'Complete identity verification and consent so the wallet sends the Credential Request.',
        `Observe the wallet rejection caused by ${defectLabel} and keep this command running.`
      ]
    },
    missingRequiredEventPolicy: 'inconclusive'
  };
}

export const wp060TypeMismatchScenario = createWp060Scenario('type-mismatch');

// export const wp060SchemaInvalidScenario = createWp060Scenario('schema-invalid');

export const wp060Scenarios: ProtocolObservedScenarioDefinition[] = [
  wp060TypeMismatchScenario
  // wp060SchemaInvalidScenario
];
