import {
  authorizationErrorResponseReceived,
  authorizationResponseForbidden,
  createNegativePresentationScenario,
  requestObjectRequested,
  rpFaultApplied
} from './presentation-evidence.js';

/** The Request Object parameter this scenario omits: REQUIRED by OpenID4VP, and detectable without any cryptographic or federation context. */
const OMITTED_PARAMETER = 'nonce';

/**
 * WP_090: the Request Object is validly signed and its `iss`, `client_id` and
 * `response_uri` are nominal, but the REQUIRED `nonce` parameter is missing.
 *
 * A validly signed Request Object is deliberate: the wallet can verify it, trust
 * its `response_uri`, and is therefore expected to report the defect there. That
 * is the observable this scenario demands, so a wallet that stops silently is
 * reported as a failure rather than as inconclusive — unlike WP_085, whose
 * broken signature makes a silent abort a legitimate outcome.
 */
export const wp090Scenario = createNegativePresentationScenario({
  id: 'WP_090',
  title: 'Negative Path: Wallet Instance reports a malformed Request Object to the response_uri',
  rpFault: { type: 'request-object-missing-parameter', parameter: OMITTED_PARAMETER },
  requiredEvents: [
    requestObjectRequested('GET'),
    rpFaultApplied('/auth/request/:state', 'request-object-missing-parameter', {
      omittedParameter: OMITTED_PARAMETER
    }),
    authorizationErrorResponseReceived
  ],
  forbiddenEvents: [authorizationResponseForbidden],
  // The error report is the normative requirement under test, so its absence is
  // a failure and not merely missing evidence.
  missingRequiredEventPolicy: 'fail',
  instructions: {
    goal: 'Verify that the Wallet Instance rejects a malformed Request Object and sends an Authorization Error Response to the Relying Party response_uri endpoint.',
    expectedBehavior: `The wallet retrieves a validly signed Request Object that omits the REQUIRED ${OMITTED_PARAMETER} parameter. It must reject the request and POST an Authorization Error Response — an error code, optionally with an error_description — to the response_uri, and it must not present any credential.`,
    observation: [
      'Keep the wallet and the test process running while the wallet retrieves and validates the Request Object.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports the invalid request to the Relying Party and stops.'
    ]
  }
});
