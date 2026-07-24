import { z } from 'zod';

/**
 * Top-level Credential Response parameters that may be omitted to exercise
 * the wallet's required-parameter validation for an immediate issuance
 * response (see the IT-Wallet Credential Response table). Kept intentionally
 * narrow to `credentials`, the minimal deterministic violation: every array
 * element's nested `credential` member is a candidate for a future,
 * separately implemented and tested variant.
 */
export const credentialResponseFaultParameters = ['credentials'] as const;

export type CredentialResponseFaultParameter = (typeof credentialResponseFaultParameters)[number];

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

/**
 * Discriminator kept stable as `edc-missing-required-claims` for backward
 * compatibility with the IPC protocol and scenario declarations, even though
 * the profile now targets the Credential Response wrapper rather than the
 * Entity Configuration: it omits one or more mandatory top-level parameters
 * from an immediate issuance response instead of dropping EDC claims.
 */
const edcMissingRequiredClaimsProfileSchema = z
  .object({
    type: z.literal('edc-missing-required-claims'),
    parameters: z.array(z.enum(credentialResponseFaultParameters)).min(1)
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
 * profiles. `invalid-trust-anchor`, `edc-missing-required-claims` and `unsupported-credential-offer` are
 * wired to a mutation today; the remaining variants are reserved so the
 * shared type, IPC protocol, and catalog metadata do not drift as future
 * fault scenarios are implemented.
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
