import { z } from 'zod';

const entityConfigurationNonmatchingSigningKeyProfileSchema = z
  .object({
    type: z.literal('entity-configuration-nonmatching-signing-key')
  })
  .strict();

/**
 * Runtime-validated, discriminated catalog of Trust Anchor fault profiles.
 * Kept separate from `IssuerFaultProfile` so issuer services cannot
 * accidentally accept Trust Anchor-only mutations.
 */
export const trustAnchorFaultProfileSchema = z.discriminatedUnion('type', [
  entityConfigurationNonmatchingSigningKeyProfileSchema
]);

export type TrustAnchorFaultProfile = z.infer<typeof trustAnchorFaultProfileSchema>;

export type TrustAnchorFaultProfileType = TrustAnchorFaultProfile['type'];

/** Validates an untrusted, already-parsed-JSON Trust Anchor fault profile payload. */
export function parseTrustAnchorFaultProfile(value: unknown): TrustAnchorFaultProfile | undefined {
  const result = trustAnchorFaultProfileSchema.safeParse(value);
  return result.success ? result.data : undefined;
}
