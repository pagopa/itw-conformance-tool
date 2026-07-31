import {
  createNegativePresentationScenario,
  requestObjectRetrievalForbidden,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_081: the Relying Party publishes an
 * `openid_credential_verifier.request_uris` list that does not contain the
 * `request_uri` the engagement handed to the wallet. The list entry differs by
 * path, so neither exact nor prefix matching can accept it.
 *
 * The live `request_uri` endpoint keeps working, so a wallet that skips the
 * check is observed retrieving the Request Object from an endpoint no trusted
 * third party attested — which is exactly the endpoint mix-up the check exists
 * to prevent.
 */
export const wp081Scenario = createNegativePresentationScenario({
  id: 'WP_081',
  // Only an openid_federation engagement makes a wallet read the Entity
  // Configuration this scenario's fault mutates.
  clientIdPrefix: 'openid_federation',
  title: 'Negative Path: Wallet Instance rejects a request_uri that the Relying Party metadata does not attest',
  rpFault: { type: 'unattested-request-uri' },
  requiredEvents: [rpFaultApplied('/.well-known/openid-federation', 'unattested-request-uri')],
  forbiddenEvents: [requestObjectRetrievalForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance checks the engagement request_uri against the request_uris attested in the Relying Party metadata and only proceeds on a match.',
    expectedBehavior:
      'The wallet requests the Relying Party Entity Configuration and finds that the request_uri it received in the engagement is absent from openid_credential_verifier.request_uris. It must terminate the presentation without sending any request to that request_uri. Successful conformance is rejection, not retrieval.',
    observation: [
      'Keep the wallet and the test process running while the wallet resolves the Relying Party metadata.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports an error about the presentation request and stops.'
    ]
  }
});
