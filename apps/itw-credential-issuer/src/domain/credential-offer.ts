/**
 * OpenID4VCI Credential Offer (by value) domain helpers.
 *
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential-offer
 * @see https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/credential-issuance-low-level.html#credential-offer-flow
 */
export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: { authorization_code: Record<string, never> };
}

export const CREDENTIAL_OFFER_URI_SCHEME = 'openid-credential-offer://';
export const CREDENTIAL_OFFER_QUERY_PARAM = 'credential_offer';

/**
 * Raised at issuer startup when `credential-issuer.credential_identifiers`
 * (or its CLI override) references identifiers that are not keys of the
 * issuer's `credential_configurations_supported` metadata map.
 */
export class UnsupportedCredentialIdentifiersError extends Error {
  readonly unsupportedIdentifiers: string[];
  readonly supportedIdentifiers: string[];

  constructor(unsupportedIdentifiers: string[], supportedIdentifiers: string[]) {
    super(
      `Unsupported credential identifier(s) configured in credential-issuer.credential_identifiers: ` +
        `${unsupportedIdentifiers.join(', ')}. Supported identifiers are: ${supportedIdentifiers.join(', ') || '(none)'}.`
    );
    this.name = 'UnsupportedCredentialIdentifiersError';
    this.unsupportedIdentifiers = unsupportedIdentifiers;
    this.supportedIdentifiers = supportedIdentifiers;
    Object.setPrototypeOf(this, UnsupportedCredentialIdentifiersError.prototype);
  }
}

/**
 * Validates that every configured credential identifier matches a key of the
 * issuer's `credential_configurations_supported` metadata map.
 *
 * @throws {UnsupportedCredentialIdentifiersError} if any identifier is unsupported.
 */
export function validateCredentialIdentifiers(identifiers: string[], supportedIdentifiers: string[]): void {
  const supported = new Set(supportedIdentifiers);
  const unsupported = identifiers.filter((identifier) => !supported.has(identifier));

  if (unsupported.length > 0) {
    throw new UnsupportedCredentialIdentifiersError(unsupported, supportedIdentifiers);
  }
}

/**
 * Builds the OpenID4VCI Credential Offer object for an Authorization Code
 * Flow, by value. `issuer_state` and `authorization_server` are intentionally
 * omitted (see plan for rationale).
 */
export function buildCredentialOffer(baseURL: string, credentialConfigurationIds: string[]): CredentialOffer {
  return {
    credential_issuer: baseURL,
    credential_configuration_ids: credentialConfigurationIds,
    grants: { authorization_code: {} }
  };
}

/**
 * Serializes a Credential Offer object into the `openid-credential-offer://`
 * by-value URI. `JSON.stringify` produces compact JSON with no whitespace, so
 * `URLSearchParams` percent-encoding is equivalent to strict RFC 3986
 * percent-encoding for this payload.
 */
export function createCredentialOfferUri(offer: CredentialOffer): string {
  const params = new URLSearchParams();
  params.set(CREDENTIAL_OFFER_QUERY_PARAM, JSON.stringify(offer));

  return `${CREDENTIAL_OFFER_URI_SCHEME}?${params.toString()}`;
}

/**
 * Validates the configured identifiers against the issuer's supported
 * credential configurations and, if valid, builds the by-value Credential
 * Offer URI.
 *
 * @throws {UnsupportedCredentialIdentifiersError} if any identifier is unsupported.
 */
export function createValidatedCredentialOfferUri(
  baseURL: string,
  credentialConfigurationIds: string[],
  supportedIdentifiers: string[]
): string {
  validateCredentialIdentifiers(credentialConfigurationIds, supportedIdentifiers);

  return createCredentialOfferUri(buildCredentialOffer(baseURL, credentialConfigurationIds));
}
