import {
  authorizationResponseForbidden,
  createNegativePresentationScenario,
  requestObjectRequested,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_086: the Request Object is validly signed, but its `iss` claim is neither
 * the `client_id` carried by the engagement nor the `sub` of the Relying Party
 * Entity Configuration. Only that one claim changes, so the signature check
 * (WP_085) still succeeds and the client identifier consistency check is the
 * only thing that can stop the flow.
 */
export const wp086Scenario = createNegativePresentationScenario({
  id: 'WP_086',
  title: 'Negative Path: Wallet Instance rejects a Request Object whose iss does not match the client_id',
  rpFault: { type: 'request-object-invalid-client-id' },
  requiredEvents: [
    requestObjectRequested('GET'),
    rpFaultApplied('/auth/request/:state', 'request-object-invalid-client-id', { mutatedClaim: 'iss' })
  ],
  forbiddenEvents: [authorizationResponseForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance confirms the Request Object iss claim equals both the engagement client_id and the sub of the Relying Party Entity Configuration.',
    expectedBehavior:
      'The wallet retrieves a validly signed Request Object whose iss claim differs from the client_id it received in the engagement and from the Relying Party Entity Configuration sub. It must not present any credential: no Authorization Response carrying a vp_token may reach the response_uri.',
    observation: [
      'Keep the wallet and the test process running while the wallet retrieves and validates the Request Object.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports an inconsistent presentation request and stops.'
    ]
  }
});
