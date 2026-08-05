import {
  createNegativePresentationScenario,
  requestObjectRetrievalForbidden,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_080: the Relying Party Entity Configuration carries a Trust Mark of the
 * nominal type, with nominal claims and `kid`, but signed with an ephemeral key
 * published nowhere in the federation, so its signature cannot be verified.
 *
 * The Trust Chain itself stays intact, which isolates Trust Mark validation from
 * WP_079; and the Trust Mark is present, which isolates it from WP_087, where
 * the Relying Party has no Trust Mark at all.
 */
export const wp080Scenario = createNegativePresentationScenario({
  id: 'WP_080',
  // Only an openid_federation engagement makes a wallet read the Entity
  // Configuration this scenario's fault mutates.
  clientIdPrefix: 'openid_federation',
  title: 'Negative Path: Wallet Instance rejects a Relying Party whose Trust Mark signature cannot be verified',
  rpFault: { type: 'invalid-trust-mark' },
  requiredEvents: [rpFaultApplied('/.well-known/openid-federation', 'invalid-trust-mark')],
  forbiddenEvents: [requestObjectRetrievalForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance evaluates the Trust Marks in the Relying Party Entity Configuration and stops when one cannot be validated.',
    expectedBehavior:
      'The wallet requests the Relying Party Entity Configuration and finds a Trust Mark whose signature does not verify against any key the federation publishes for the Relying Party. It must terminate the presentation without retrieving the Request Object. Successful conformance is rejection, not presentation.',
    observation: [
      'Keep the wallet and the test process running while the wallet resolves the Trust Anchor and evaluates the Relying Party Trust Mark.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports a trust error and stops.'
    ]
  }
});
