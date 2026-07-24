import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

/** The default `credential_configuration_id` used by legacy interactive issuance scenarios. */
export const NOMINAL_CREDENTIAL_CONFIGURATION_ID = 'dc_sd_jwt_EuropeanDisabilityCard';

export interface CredentialOfferPayload {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: {
    authorization_code: {
      issuer_state: string;
    };
  };
}

/** Builds the nominal, unmutated Credential Offer for a `credential-offer` stimulus. */
export function buildCredentialOffer(
  credentialIssuer: string,
  correlationId: string,
  credentialConfigurationId = NOMINAL_CREDENTIAL_CONFIGURATION_ID
): CredentialOfferPayload {
  return {
    credential_issuer: credentialIssuer,
    credential_configuration_ids: [credentialConfigurationId],
    grants: {
      authorization_code: {
        issuer_state: correlationId
      }
    }
  };
}

/**
 * Applies the `unsupported-credential-offer` fault profile to a nominal
 * Credential Offer: replaces the single `credential_configuration_ids` entry
 * with the profile's `credentialConfigurationId`, leaving `credential_issuer`
 * and `issuer_state` (the scenario correlation id) untouched. Unlike the
 * other issuer fault profiles, this mutation is applied by the conformance
 * runner itself (see `runner/scenario-runner.ts`), not by a Credential
 * Issuer HTTP response, because the Credential Offer for interactive
 * scenarios is built and shown by the runner rather than served by
 * `apps/itw-credential-issuer`'s `/credential-offer` route.
 */
export function applyUnsupportedCredentialOfferFault(
  offer: CredentialOfferPayload,
  profile: Extract<IssuerFaultProfile, { type: 'unsupported-credential-offer' }>
): CredentialOfferPayload {
  return {
    ...offer,
    credential_configuration_ids: [profile.credentialConfigurationId]
  };
}

/**
 * Applies `issuerFault` to `offer` when the fault's application point is
 * this helper's concern (`unsupported-credential-offer`); every other fault
 * profile has a different application point and leaves the offer unchanged.
 */
export function applyIssuerFaultToCredentialOffer(
  offer: CredentialOfferPayload,
  issuerFault: IssuerFaultProfile | undefined
): CredentialOfferPayload {
  if (issuerFault?.type !== 'unsupported-credential-offer') return offer;
  return applyUnsupportedCredentialOfferFault(offer, issuerFault);
}

export function serializeCredentialOfferUri(offer: CredentialOfferPayload): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/**
 * Builds and serializes the Credential Offer shown for a `credential-offer`
 * stimulus. When `issuerFault` is the already-activated
 * `unsupported-credential-offer` profile, the offer carries the profile's
 * unsupported `credential_configuration_id` instead of the nominal one; any
 * other fault profile (a different application point) leaves the offer
 * nominal.
 */
export function createCredentialOfferUri(
  credentialIssuer: string,
  correlationId: string,
  issuerFault?: IssuerFaultProfile,
  credentialConfigurationId = NOMINAL_CREDENTIAL_CONFIGURATION_ID
): string {
  const offer = applyIssuerFaultToCredentialOffer(
    buildCredentialOffer(credentialIssuer, correlationId, credentialConfigurationId),
    issuerFault
  );
  return serializeCredentialOfferUri(offer);
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
