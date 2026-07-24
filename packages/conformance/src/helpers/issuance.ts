export function createCredentialOfferUri(credentialIssuer: string, correlationId: string): string {
  const credentialOffer = {
    credential_issuer: credentialIssuer,
    credential_configuration_ids: ['dc_sd_jwt_EuropeanDisabilityCard'],
    grants: {
      authorization_code: {
        issuer_state: correlationId
      }
    }
  };

  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`;
}

const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * Validates a PKCE code_verifier against RFC 7636 §4.1: a high-entropy
 * cryptographic random string using the unreserved character set
 * (ALPHA / DIGIT / "-" / "." / "_" / "~"), 43–128 characters long.
 */
export function isRfc7636CodeVerifier(value: string): boolean {
  return PKCE_CODE_VERIFIER_PATTERN.test(value);
}
