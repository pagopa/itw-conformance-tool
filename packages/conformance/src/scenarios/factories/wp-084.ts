import {
  authorizationResponseReceived,
  presentationTimeouts,
  relyingPartySubordinateStatementRequested,
  requestObjectRequested,
  rpEntityConfigurationRequested,
  rpFaultApplied,
  trustAnchorEntityConfigurationRequested,
  vpTokenValidationSucceeded
} from './presentation-evidence.js';

import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * WP_084: the wallet must obtain the Relying Party's public key exclusively from
 * `metadata.openid_credential_verifier.jwks` in the Entity Configuration reached
 * through the Trust Chain, selecting it by the `kid` in the Request Object
 * header.
 *
 * Unlike the other Relying Party fault scenarios this is a **happy path**: the
 * Request Object is nominal and validly signed, and a conformant wallet is
 * expected to complete the presentation. The scenario's job is to remove every
 * key source other than the federation metadata, which is what the Test Matrix
 * requires to make the case conclusive — the key must exist nowhere else in the
 * test ecosystem, otherwise a wallet that never consults the federation would
 * pass anyway. The `request-object-federation-key` profile does exactly that: it
 * drops the `x5c` certificate chain (and any inlined `trust_chain`) from the
 * header and switches the `client_id` to the `openid_federation` prefix, leaving
 * `kid` as the only handle on the signing key.
 *
 * A wallet that skips the metadata fetch therefore cannot verify the Request
 * Object, and the flow stops before the Authorization Response — which is what
 * makes the successful completion here meaningful rather than incidental.
 */
export const wp084Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_084',
  title: 'Happy Path: Wallet Instance resolves the Relying Party public key from the federation metadata alone',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty', 'federation'],
  stimulus: {
    type: 'presentation-request',
    delivery: ['deep-link']
  },
  setup: { rpFault: { type: 'request-object-federation-key' } },
  entryEvent: 'rp.metadata.requested',
  requiredEvents: [
    // The Entity Configuration fetch is the whole point of this case: it is the
    // only place the verification key is published once `x5c` is gone.
    rpEntityConfigurationRequested,
    trustAnchorEntityConfigurationRequested,
    relyingPartySubordinateStatementRequested,
    requestObjectRequested('GET'),
    rpFaultApplied('/auth/request/:state', 'request-object-federation-key'),
    // Reaching a valid Authorization Response proves the wallet actually
    // resolved the key: with no `x5c` in the header there is no other way it
    // could have verified the Request Object it just accepted.
    authorizationResponseReceived,
    vpTokenValidationSucceeded
  ],
  forbiddenEvents: ['vp_token.validation.failed', 'rp.presentation_error.received'],
  timeouts: { ...presentationTimeouts, forbiddenObservationMs: 5_000, vitestTestMs: 330_000 },
  verdictRules: [
    { type: 'entry-event-required' },
    { type: 'required-events-in-order' },
    { type: 'no-forbidden-events-after-entry' }
  ],
  instructions: {
    goal: 'Verify that the Wallet Instance fetches the Relying Party public key from metadata.openid_credential_verifier.jwks in the Entity Configuration, using the kid in the Request Object header, and that it can complete a presentation when that is the only place the key is published.',
    expectedBehavior:
      'The wallet resolves the Relying Party Entity Configuration and Trust Chain from the Trust Anchor, retrieves a Request Object whose header carries no x5c certificate chain, looks the header kid up in metadata.openid_credential_verifier.jwks to verify the signature, and completes the flow with an encrypted Authorization Response. A wallet that can only verify a Request Object from an x5c header will stop here instead.',
    prerequisites: [
      'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
      'The wallet supports the openid_federation Client Identifier Prefix and resolves Relying Party keys through the federation Trust Chain; a wallet that requires an x5c certificate chain in the Request Object header cannot satisfy this scenario.',
      'The wallet can open presentation request deep links on the same device (same-device flow).',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Start this scenario with itwct test presentation. The CLI starts the required Trust Anchor and Relying Party services, activates the request-object-federation-key profile on the Relying Party, and waits for their readiness.',
      'Open the printed presentation request deep link with the Wallet Instance on the same device.',
      'Allow the wallet to resolve the Relying Party federation trust chain and retrieve the Request Object.',
      'Approve the disclosure of the requested attributes in the wallet.',
      'The runner passes once the Relying Party receives a valid Authorization Response for a Request Object the wallet could only have verified with the federation-published key.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
