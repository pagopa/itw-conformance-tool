import { z } from 'zod';

/**
 * WP_079: replaces the Relying Party Entity Configuration `authority_hints`
 * with a syntactically valid Entity ID that can never be a federation
 * participant, so the wallet cannot build a Trust Chain from the configured
 * Trust Anchor down to the Relying Party. Mutated inside the claims, before
 * signing, so the Entity Configuration stays validly signed and only its
 * federation position is defective.
 */
const invalidTrustAnchorProfileSchema = z
  .object({
    type: z.literal('invalid-trust-anchor')
  })
  .strict();

/**
 * WP_080: keeps the nominal Trust Mark type and claims but signs the Trust
 * Mark with an ephemeral key that is published nowhere in the federation, so
 * its signature cannot be verified against the Relying Party's federation
 * JWKS. Isolates Trust Mark validation from
 * `missing-presentation-trust-mark` (WP_087), where the Trust Mark is absent
 * rather than unverifiable.
 */
const invalidTrustMarkProfileSchema = z
  .object({
    type: z.literal('invalid-trust-mark')
  })
  .strict();

/**
 * WP_081: publishes an `openid_credential_verifier.request_uris` list that
 * does not contain the `request_uri` handed to the wallet in the engagement,
 * while the engagement itself keeps pointing at the live Request Object
 * endpoint. A conformant wallet must refuse to fetch a `request_uri` that the
 * federation does not attest; a wallet that fetches it anyway is observed
 * doing so on the real endpoint.
 */
const unattestedRequestUriProfileSchema = z
  .object({
    type: z.literal('unattested-request-uri')
  })
  .strict();

/**
 * WP_091a: publishes an `openid_credential_verifier.response_uris` list that
 * does not contain the `response_uri` carried by the Request Object, while
 * the Request Object keeps pointing at the live Authorization Response
 * endpoint. A conformant wallet must not post the Authorization Response to
 * an unattested `response_uri`; a wallet that posts anyway is observed doing
 * so on the real endpoint.
 */
const unattestedResponseUriProfileSchema = z
  .object({
    type: z.literal('unattested-response-uri')
  })
  .strict();

/**
 * WP_087: serves an Entity Configuration with no Trust Mark at all, so the
 * federation does not attest the Relying Party's permission to request
 * Digital Credential presentations, while every other metadata member stays
 * nominal.
 */
const missingPresentationTrustMarkProfileSchema = z
  .object({
    type: z.literal('missing-presentation-trust-mark')
  })
  .strict();

/**
 * WP_085 (and WP_090's error-response requirement): serves a Request Object
 * whose header and payload are nominal, but whose signature was produced with
 * an ephemeral key, so it verifies against neither the `x5c` leaf certificate
 * nor the federation-published `kid`.
 */
const requestObjectInvalidSignatureProfileSchema = z
  .object({
    type: z.literal('request-object-invalid-signature')
  })
  .strict();

/**
 * WP_086: serves a validly signed Request Object whose `iss` claim is neither
 * the `client_id` used in the engagement nor the `sub` of the Relying Party
 * Entity Configuration, isolating the client identifier consistency check
 * from the signature check (`request-object-invalid-signature`).
 */
const requestObjectInvalidClientIdProfileSchema = z
  .object({
    type: z.literal('request-object-invalid-client-id')
  })
  .strict();

/**
 * WP_084: serves a Request Object signed the OpenID Federation way instead of
 * the X.509 way. The JOSE header carries only `alg`, `kid` and `typ` — no `x5c`
 * certificate chain and no embedded `trust_chain` — and the `client_id` switches
 * from the `x509_hash` Client Identifier Prefix to `openid_federation`.
 *
 * Nothing about the Request Object is defective: it stays validly signed with
 * the same Relying Party key, and that key is published in
 * `metadata.openid_credential_verifier.jwks`. What changes is that the key is
 * published *only* there — with the certificate chain gone from the header, the
 * sole way to obtain it is to resolve the Relying Party Entity Configuration
 * through the Trust Chain and select the key by the header's `kid`. A wallet
 * that never fetches that metadata cannot verify the Request Object at all.
 *
 * The Client Identifier Prefix has to change with it: `x509_hash` tells a wallet
 * to take the key from the header's `x5c`, which is exactly the path this
 * profile removes. The prefixed and unprefixed identifiers still resolve to the
 * same entity, so the engagement `client_id`, the Request Object `iss` and the
 * Entity Configuration `sub` stay consistent (WP_086).
 */
const requestObjectFederationKeyProfileSchema = z
  .object({
    type: z.literal('request-object-federation-key')
  })
  .strict();

/**
 * WP_090: serves a validly signed Request Object that omits one required
 * OpenID4VP parameter, so the wallet must reject it and report the failure to
 * the `response_uri` as an Authorization Error Response. Kept intentionally
 * narrow to `response_type` and `nonce`, the two parameters whose absence a
 * wallet can detect without any federation or cryptographic context.
 */
export const requestObjectOmittedParameters = ['response_type', 'nonce'] as const;

export type RequestObjectOmittedParameter = (typeof requestObjectOmittedParameters)[number];

const requestObjectMissingParameterProfileSchema = z
  .object({
    type: z.literal('request-object-missing-parameter'),
    parameter: z.enum(requestObjectOmittedParameters)
  })
  .strict();

/**
 * WP_094a: publishes an `openid_credential_verifier.redirect_uris` list that
 * does not contain the `redirect_uri` the Relying Party returns with the
 * Authorization Response, while that response keeps pointing at the live
 * callback endpoint. A conformant wallet must not redirect the user-agent to a
 * `redirect_uri` the federation does not attest; a wallet that redirects anyway
 * is observed landing on the real endpoint.
 */
const unattestedRedirectUriProfileSchema = z
  .object({
    type: z.literal('unattested-redirect-uri')
  })
  .strict();

/**
 * Runtime-validated, discriminated catalog of Relying Party fault profiles.
 * Kept separate from `IssuerFaultProfile` because the two services own
 * different response pipelines and different activation channels, even though
 * both follow the same activate/apply/deactivate lifecycle (see
 * `docs/rp-fault-profile-lifecycle.md`).
 */
export const rpFaultProfileSchema = z.discriminatedUnion('type', [
  invalidTrustAnchorProfileSchema,
  invalidTrustMarkProfileSchema,
  unattestedRequestUriProfileSchema,
  unattestedResponseUriProfileSchema,
  missingPresentationTrustMarkProfileSchema,
  requestObjectInvalidSignatureProfileSchema,
  requestObjectInvalidClientIdProfileSchema,
  requestObjectFederationKeyProfileSchema,
  requestObjectMissingParameterProfileSchema,
  unattestedRedirectUriProfileSchema
]);

export type RpFaultProfile = z.infer<typeof rpFaultProfileSchema>;

export type RpFaultProfileType = RpFaultProfile['type'];

/** Validates an untrusted, already-parsed-JSON fault profile payload. */
export function parseRpFaultProfile(value: unknown): RpFaultProfile | undefined {
  const result = rpFaultProfileSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
