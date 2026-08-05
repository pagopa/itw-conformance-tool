import {
  authorizationResponseForbidden,
  createNegativePresentationScenario,
  requestObjectRequested,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_086: the Request Object is validly signed, but its `iss` claim is neither
 * the identifier the engagement `client_id` carries nor the `sub` of the Relying
 * Party Entity Configuration. Only that one claim changes, so the signature
 * check (WP_085) still succeeds and the client identifier consistency check is
 * the only thing that can stop the flow.
 *
 * The engagement announces the `openid_federation` prefix because that is the
 * only trust model in which this check exists: the identifier behind an
 * `openid_federation` `client_id` *is* the entity identifier, so a wallet can
 * compare it with `iss` and with the Entity Configuration `sub`. Under
 * `x509_hash` the `client_id` is a certificate hash that names no entity, and
 * the Entity Configuration is never fetched, so there would be nothing to
 * compare `iss` against and a conformant wallet could legitimately accept the
 * mutated Request Object.
 *
 * The Request Object header inlines the Trust Chain — the Relying Party Entity
 * Configuration, the Trust Anchor Subordinate Statement about it, and the Trust
 * Anchor Entity Configuration — so the `sub` the mutated `iss` contradicts
 * travels in the artifact under test itself. That removes the last excuse for
 * accepting it: the wallet does not have to have resolved, cached or refreshed
 * anything to hold both values at once, and a wallet that presents anyway
 * skipped a comparison it could make locally.
 */
export const wp086Scenario = createNegativePresentationScenario({
  id: 'WP_086',
  clientIdPrefix: 'openid_federation',
  inlineTrustChain: true,
  title: 'Negative Path: Wallet Instance rejects a Request Object whose iss does not match the client_id',
  rpFault: { type: 'request-object-invalid-client-id' },
  requiredEvents: [
    requestObjectRequested('GET', undefined, { inlineTrustChain: true }),
    rpFaultApplied('/auth/request/:state', 'request-object-invalid-client-id', { mutatedClaim: 'iss' })
  ],
  forbiddenEvents: [authorizationResponseForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance confirms the Request Object iss claim equals both the identifier carried by the engagement client_id and the sub of the Relying Party Entity Configuration.',
    expectedBehavior:
      'The wallet retrieves a validly signed Request Object whose header carries the federation Trust Chain and whose iss claim differs from the identifier the engagement client_id carries and from the Relying Party Entity Configuration sub. It must not present any credential: no Authorization Response carrying a vp_token may reach the response_uri.',
    observation: [
      'Keep the wallet and the test process running while the wallet retrieves and validates the Request Object.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports an inconsistent presentation request and stops.'
    ]
  }
});
