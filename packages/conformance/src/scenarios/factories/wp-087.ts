import {
  createNegativePresentationScenario,
  requestObjectRetrievalForbidden,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_087: the Relying Party Entity Configuration carries no Trust Mark at all,
 * so the federation does not attest that this Relying Party may request Digital
 * Credential presentations. Every other member — the Trust Chain, the verifier
 * metadata, the keys — stays nominal, isolating the authorization decision from
 * WP_079 (broken chain) and WP_080 (unverifiable Trust Mark).
 */
export const wp087Scenario = createNegativePresentationScenario({
  id: 'WP_087',
  // Only an openid_federation engagement makes a wallet read the Entity
  // Configuration this scenario's fault mutates.
  clientIdPrefix: 'openid_federation',
  title:
    'Negative Path: Wallet Instance rejects a Relying Party the federation does not authorize to request presentations',
  rpFault: { type: 'missing-presentation-trust-mark' },
  requiredEvents: [rpFaultApplied('/.well-known/openid-federation', 'missing-presentation-trust-mark')],
  forbiddenEvents: [requestObjectRetrievalForbidden],
  instructions: {
    goal: "Verify that the Wallet Instance authorizes a presentation only when the Relying Party's metadata, policies and Trust Marks together confirm it may request the credentials.",
    expectedBehavior:
      'The wallet requests the Relying Party Entity Configuration and finds no Trust Mark attesting the relying_party presentation capability. It must terminate the presentation without retrieving the Request Object. Successful conformance is rejection, not presentation.',
    summary: 'Verify rejection of a Relying Party not authorized to request presentations.',
    observation: [
      'Let the wallet resolve the Relying Party metadata and its federation authorizations.',
      'Do not approve any disclosure: the expected outcome is that the wallet refuses the unauthorized Relying Party and stops.'
    ]
  }
});
