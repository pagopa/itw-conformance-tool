import { z } from 'zod';

/**
 * Claims that may be dropped from an Entity Configuration (EDC) response to
 * exercise the wallet's required-claim validation. Kept intentionally narrow
 * to the claims that are meaningful to omit without producing a structurally
 * unparsable JWT payload.
 */
export const edcRequiredClaims = ['iss', 'sub', 'jwks', 'metadata', 'authority_hints', 'trust_marks'] as const;

export type EdcRequiredClaim = (typeof edcRequiredClaims)[number];

const invalidTrustAnchorProfileSchema = z
  .object({
    type: z.literal('invalid-trust-anchor')
  })
  .strict();

const unsupportedCredentialOfferProfileSchema = z
  .object({
    type: z.literal('unsupported-credential-offer'),
    credentialConfigurationId: z.string().min(1)
  })
  .strict();

const invalidPolicyOrTrustMarkProfileSchema = z
  .object({
    type: z.literal('invalid-policy-or-trust-mark'),
    target: z.enum(['policy', 'trust-mark'])
  })
  .strict();

const authorizationResponseMissingClaimProfileSchema = z
  .object({
    type: z.literal('authorization-response-missing-claim'),
    claim: z.enum(['code', 'state', 'iss'])
  })
  .strict();

const authorizationResponseInvalidStateProfileSchema = z
  .object({
    type: z.literal('authorization-response-invalid-state')
  })
  .strict();

const authorizationResponseInvalidIssuerProfileSchema = z
  .object({
    type: z.literal('authorization-response-invalid-issuer')
  })
  .strict();

const edcMissingRequiredClaimsProfileSchema = z
  .object({
    type: z.literal('edc-missing-required-claims'),
    claims: z.array(z.enum(edcRequiredClaims)).min(1)
  })
  .strict();

const edcInvalidTrustChainProfileSchema = z
  .object({
    type: z.literal('edc-invalid-trust-chain')
  })
  .strict();

const edcInvalidSignatureProfileSchema = z
  .object({
    type: z.literal('edc-invalid-signature')
  })
  .strict();

const mdlInvalidSignatureProfileSchema = z
  .object({
    type: z.literal('mdl-invalid-signature')
  })
  .strict();

/**
 * Runtime-validated, discriminated catalog of Credential Issuer fault
 * profiles. `invalid-trust-anchor`, `authorization-response-missing-claim`,
 * `authorization-response-invalid-state`, and
 * `authorization-response-invalid-issuer` are wired to a mutation today; the
 * remaining variants are reserved so the shared type, IPC protocol, and
 * catalog metadata do not drift as future fault scenarios are implemented.
 */
export const issuerFaultProfileSchema = z.discriminatedUnion('type', [
  invalidTrustAnchorProfileSchema,
  unsupportedCredentialOfferProfileSchema,
  invalidPolicyOrTrustMarkProfileSchema,
  authorizationResponseMissingClaimProfileSchema,
  authorizationResponseInvalidStateProfileSchema,
  authorizationResponseInvalidIssuerProfileSchema,
  edcMissingRequiredClaimsProfileSchema,
  edcInvalidTrustChainProfileSchema,
  edcInvalidSignatureProfileSchema,
  mdlInvalidSignatureProfileSchema
]);

export type IssuerFaultProfile = z.infer<typeof issuerFaultProfileSchema>;

export type IssuerFaultProfileType = IssuerFaultProfile['type'];

/** Validates an untrusted, already-parsed-JSON fault profile payload. */
export function parseIssuerFaultProfile(value: unknown): IssuerFaultProfile | undefined {
  const result = issuerFaultProfileSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
