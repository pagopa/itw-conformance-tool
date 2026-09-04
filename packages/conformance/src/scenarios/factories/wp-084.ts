import {
  authorizationResponseReceived,
  federationDiscoveryEvidence,
  presentationEntryEvent,
  presentationTimeouts,
  requestObjectRequested,
  vpTokenValidationSucceeded
} from './presentation-evidence.js';

import type { ProtocolObservedScenarioDefinition } from '../definitions.js';

/**
 * WP_084: the wallet must obtain the Relying Party's public key exclusively from
 * `metadata.openid_credential_verifier.jwks` in the Entity Configuration reached
 * through the Trust Chain, selecting it by the `kid` in the Request Object
 * header.
 *
 * Unlike the negative Relying Party scenarios this is a **happy path**: nothing
 * is defective, and a conformant wallet is expected to complete the
 * presentation. What makes the case conclusive is the trust model the engagement
 * announces. With the `openid_federation` Client Identifier Prefix the Relying
 * Party serves a Request Object whose header carries only `alg`, `kid` and
 * `typ` — no `x5c` certificate chain and no inlined `trust_chain` — so the
 * signing key exists nowhere in the test ecosystem except the federation
 * metadata, and a wallet that never fetches it cannot verify the Request Object
 * at all.
 *
 * This is therefore also the scenario that exercises the federation discovery
 * itself (WP_078): the Relying Party Entity Configuration, the Trust Anchor
 * Entity Configuration and the subordinate statement that binds the two. The
 * `x509_hash` scenarios cannot cover it — their `client_id` is a certificate
 * hash that names no entity, so there is nothing for a wallet to resolve.
 */
export const wp084Scenario: ProtocolObservedScenarioDefinition = {
  id: 'WP_084',
  title: 'Happy Path: Wallet Instance resolves the Relying Party public key from the federation metadata alone',
  phase: 'PRESENTATION',
  automationMode: 'interactive-protocol-observed',
  services: ['relyingParty', 'federation'],
  stimulus: {
    type: 'presentation-request',
    // The whole point of the case: it is the prefix the engagement announces,
    // not a fault, that removes every key source except the federation metadata.
    clientIdPrefix: 'openid_federation',
    delivery: ['deep-link']
  },
  entryEvent: presentationEntryEvent('openid_federation'),
  requiredEvents: [
    // The Entity Configuration fetch is the whole point of this case: it is the
    // only place the verification key is published.
    ...federationDiscoveryEvidence,
    // Matching on the trust model proves what the wallet was handed: a Request
    // Object with no `x5c`, leaving the header `kid` as the only handle on the
    // signing key.
    requestObjectRequested('GET', 'openid_federation'),
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
    summary: 'Verify presentation when the Relying Party key is available only from federation metadata.',
    prerequisites: [
      'The wallet app under test is installed and holds a credential that satisfies the requested presentation (PID by default).',
      'The wallet supports the openid_federation Client Identifier Prefix and resolves Relying Party keys through the federation Trust Chain; a wallet that requires an x5c certificate chain in the Request Object header cannot satisfy this scenario.',
      'The wallet can open presentation request deep links on the same device (same-device flow).',
      'Run the test from the workspace root, where config.ini and the compiled local services are available.',
      'The device running the wallet can reach the local Trust Anchor and Relying Party URLs printed by this test.'
    ],
    steps: [
      'Open the presentation request with the Wallet Instance on the same device.',
      'Allow the wallet to resolve the Relying Party federation trust chain and retrieve the Request Object.',
      'Approve the requested disclosure in the wallet.',
      'Keep the wallet and this command running until the scenario completes.'
    ]
  },
  missingRequiredEventPolicy: 'inconclusive'
};
