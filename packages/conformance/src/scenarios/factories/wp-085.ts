import {
  authorizationResponseForbidden,
  createNegativePresentationScenario,
  requestObjectRequested,
  rpFaultApplied
} from './presentation-evidence.js';

/**
 * WP_085: the Request Object the wallet retrieves has a nominal header — same
 * `kid`, same `x5c` — and nominal claims, but its signature was produced with an
 * ephemeral key, so it verifies against neither the leaf certificate in the
 * header nor the key the federation publishes for that `kid`.
 *
 * Only an Authorization Response carrying a vp_token is forbidden. Reporting the
 * rejection to the `response_uri` is allowed here, and required by WP_090 — see
 * `wp090Scenario`, which uses a validly signed but malformed Request Object so
 * that the error report itself can be demanded without conflating the two
 * checks.
 *
 * The signature check is trust-model agnostic, so the scenario runs on the
 * nominal `x509_hash` engagement: the leaf certificate is right there in the
 * header, and the signature still fails to verify against it. No federation call
 * is expected, and the Request Object retrieval is the entry event.
 */
export const wp085Scenario = createNegativePresentationScenario({
  id: 'WP_085',
  title: 'Negative Path: Wallet Instance rejects a Request Object whose signature does not verify',
  rpFault: { type: 'request-object-invalid-signature' },
  requiredEvents: [
    requestObjectRequested('GET'),
    rpFaultApplied('/auth/request/:state', 'request-object-invalid-signature', { mutatedArtifactPart: 'signature' })
  ],
  forbiddenEvents: [authorizationResponseForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance cryptographically validates the Request Object signature and refuses to present any credential when that validation fails.',
    expectedBehavior:
      'The wallet retrieves the Request Object from the request_uri endpoint and finds a signature that does not verify against the Relying Party key. It must not present any credential: no Authorization Response carrying a vp_token may reach the response_uri. Reporting the failure to the response_uri as an Authorization Error Response is allowed, and is what WP_090 requires.',
    observation: [
      'Keep the wallet and the test process running while the wallet retrieves and verifies the Request Object.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports an invalid presentation request and stops.'
    ]
  }
});
