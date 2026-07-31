import {
  authorizationResponseReceived,
  createNegativePresentationScenario,
  relyingPartySubordinateStatementRequested,
  requestObjectRequested,
  rpFaultApplied,
  trustAnchorEntityConfigurationRequested,
  unattestedRedirectFollowForbidden,
  vpTokenValidationSucceeded
} from './presentation-evidence.js';

/**
 * WP_094a: the Relying Party publishes an
 * `openid_credential_verifier.redirect_uris` list that does not contain the
 * `redirect_uri` it returns with the Authorization Response. The list entry
 * differs by path, so neither exact nor prefix matching can accept it.
 *
 * The presentation itself is nominal and must succeed — this is the only
 * negative presentation scenario that requires a complete, valid Authorization
 * Response — because the Relying Party only hands out a `redirect_uri` once it
 * has verified the vp_token. The returned URI keeps pointing at the live
 * callback endpoint, so a wallet that redirects the user-agent without checking
 * it against the attested list is observed landing there.
 */
export const wp094aScenario = createNegativePresentationScenario({
  id: 'WP_094a',
  title:
    'Negative Path: Wallet Instance does not follow a redirect_uri that the Relying Party metadata does not attest',
  rpFault: { type: 'unattested-redirect-uri' },
  requiredEvents: [
    rpFaultApplied('/.well-known/openid-federation', 'unattested-redirect-uri'),
    trustAnchorEntityConfigurationRequested,
    relyingPartySubordinateStatementRequested,
    requestObjectRequested('GET'),
    authorizationResponseReceived,
    vpTokenValidationSucceeded
  ],
  forbiddenEvents: [unattestedRedirectFollowForbidden],
  instructions: {
    goal: 'Verify that the Wallet Instance checks the redirect_uri it receives in the Authorization Response result against the redirect_uris attested in the Relying Party metadata, and aborts the redirect when it does not match.',
    expectedBehavior:
      'The wallet completes the presentation normally and receives a redirect_uri that is absent from openid_credential_verifier.redirect_uris. It must not redirect the user-agent to it. Successful conformance is a completed presentation followed by no redirect.',
    summary: 'Verify rejection of an unattested redirect_uri after a valid presentation.',
    observation: [
      'Approve the disclosure of the requested attributes in the wallet so the presentation completes: this scenario needs a valid Authorization Response before the redirect_uri is returned.',
      'After the presentation completes, do not open the URI yourself, and watch the wallet: the expected outcome is that it does not redirect anywhere and reports that the flow ended.'
    ]
  }
});
