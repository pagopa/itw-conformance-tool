export function createCredentialOfferUri(credentialIssuer: string, correlationId: string): string {
  const credentialOffer = {
    credential_issuer: credentialIssuer,
    credential_configuration_ids: ['dc_sd_jwt_PID'],
    grants: {
      authorization_code: {
        issuer_state: correlationId
      }
    }
  };

  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`;
}
