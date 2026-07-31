import {
  createNegativePresentationScenario,
  relyingPartySubordinateStatementRequested,
  requestObjectRetrievalForbidden,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_079: the Relying Party Entity Configuration is validly signed, but its
 * `authority_hints` point at an Entity ID that can never resolve, so no Trust
 * Chain reaches the configured Trust Anchor.
 *
 * A happy path cannot show whether the wallet validates the Trust Chain at all;
 * only a broken chain can. Both continuations are forbidden: asking the
 * configured Trust Anchor for a subordinate statement about a Relying Party that
 * does not claim it as an authority, and retrieving the Request Object anyway.
 */
export const wp079Scenario = createNegativePresentationScenario({
  id: 'WP_079',
  title: 'Negative Path: Wallet Instance rejects a Relying Party whose Trust Chain does not reach the Trust Anchor',
  rpFault: { type: 'invalid-trust-anchor' },
  requiredEvents: [rpFaultApplied('/.well-known/openid-federation', 'invalid-trust-anchor')],
  forbiddenEvents: [relyingPartySubordinateStatementRequested, requestObjectRetrievalForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance validates the Relying Party OpenID Federation Trust Chain and stops when it cannot be built up to the configured Trust Anchor.',
    expectedBehavior:
      'The wallet requests the Relying Party Entity Configuration and finds authority_hints that do not include the configured Trust Anchor. It must terminate the presentation without resolving a subordinate statement for the Relying Party and without retrieving the Request Object. Successful conformance is rejection, not presentation.',
    summary: 'Verify rejection of a Relying Party whose Trust Chain does not reach the Trust Anchor.',
    observation: [
      'Let the wallet request and inspect the Relying Party Entity Configuration.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports a trust error and stops.'
    ]
  }
});
