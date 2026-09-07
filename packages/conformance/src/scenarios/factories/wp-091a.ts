import { createNegativePresentationScenario, requestObjectRequested, rpFaultApplied } from './presentation-evidence.js';

/**
 * WP_091a: the Relying Party publishes an
 * `openid_credential_verifier.response_uris` list that does not contain the
 * `response_uri` carried by the Request Object. The list entry differs by path,
 * so neither exact nor prefix matching can accept it.
 *
 * The Request Object itself is nominal and validly signed, and the live
 * `response_uri` endpoint keeps working, so a wallet that skips the check is
 * observed posting to an endpoint no trusted third party attested. Every post is
 * forbidden, including an Authorization Error Response: the wallet must validate
 * the `response_uri` before sending anything to it.
 */
export const wp091aScenario = createNegativePresentationScenario({
  id: 'WP_091a',
  // Only an openid_federation engagement makes a wallet read the Entity
  // Configuration this scenario's fault mutates.
  clientIdPrefix: 'openid_federation',
  title: 'Negative Path: Wallet Instance rejects a response_uri that the Relying Party metadata does not attest',
  rpFault: { type: 'unattested-response-uri' },
  requiredEvents: [
    rpFaultApplied('/.well-known/openid-federation', 'unattested-response-uri'),
    requestObjectRequested('GET')
  ],
  // Bare event name: no post to the unattested response_uri is acceptable, so
  // every occurrence counts — not just the ones carrying a vp_token.
  forbiddenEvents: ['rp.presentation_response.received'],
  instructions: {
    goal: 'Verify that the Wallet Instance confirms the Request Object response_uri is one of the response_uris attested in the Relying Party metadata before sending anything to it.',
    expectedBehavior:
      'The wallet resolves the Relying Party metadata and retrieves a nominal Request Object whose response_uri is absent from openid_credential_verifier.response_uris. It must terminate the presentation without posting to that response_uri at all — neither an Authorization Response nor an Authorization Error Response.',
    summary: 'Verify rejection of a response_uri not attested by Relying Party metadata.',
    observation: [
      'Let the wallet resolve the metadata and retrieve the Request Object.',
      'Do not approve any disclosure: the expected outcome is that the wallet reports an error about the presentation request and stops.'
    ]
  }
});
