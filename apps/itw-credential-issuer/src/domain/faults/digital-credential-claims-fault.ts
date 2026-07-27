import { createSRIHash } from '../sd-jwt.js';

import type { IssuerFaultProfile } from '@itw-conformance-tool/faults';

export type DigitalCredentialClaimsFaultProfile = Extract<
  IssuerFaultProfile,
  { type: 'digital-credential-claims-invalid' }
>;

/**
 * Reserved, collision-resistant test URN injected in place of the nominal
 * `vct` for the WP_060 `type-mismatch` variant. Distinct from any real or
 * reserved Digital Credential type identifier so the mismatch is
 * unambiguous and cannot accidentally collide with a genuine `vct`.
 */
export const WP_060_TYPE_MISMATCH_VCT = 'urn:itw-conformance-tool:wp060:type-mismatch:not-a-real-credential-type';

/** The Digital Credential Data Model claim omitted by the WP_060 `schema-invalid` variant. */
export const WP_060_OMITTED_SCHEMA_CLAIM = 'issuing_country';

export interface ApplyDigitalCredentialClaimsFaultInput {
  /** The already-validated, active WP_060 fault profile. */
  profile: DigitalCredentialClaimsFaultProfile;
  /**
   * The nominal, unsigned SD-JWT VC claims object -- including `vct` and
   * `'vct#integrity'` -- exactly as it would otherwise be passed to
   * `sdjwt.issue` with no fault active.
   */
  claims: Record<string, unknown>;
}

export type DigitalCredentialClaimsFaultMutationEvidence =
  | { readonly expectedVct: string; readonly injectedVct: string; readonly variant: 'type-mismatch' }
  | { readonly omittedClaim: typeof WP_060_OMITTED_SCHEMA_CLAIM; readonly variant: 'schema-invalid' };

export interface DigitalCredentialClaimsFaultMutation {
  /** The mutated, still-unsigned claims object; a new object, never the original reference. */
  readonly claims: Record<string, unknown>;
  /** Safe field names/identifiers only: never a claim's actual (possibly PII) value. */
  readonly evidence: DigitalCredentialClaimsFaultMutationEvidence;
}

export type ApplyDigitalCredentialClaimsFaultResult =
  { ok: true; mutation: DigitalCredentialClaimsFaultMutation } | { ok: false; reason: string };

/**
 * Pure, pre-signature mutator for the WP_060 `digital-credential-claims-invalid`
 * fault. Must be invoked on the unsigned claims object before `sdjwt.issue`, so
 * the resulting SD-JWT VC remains validly signed and only its semantic content
 * is defective -- mutating an already-serialized/signed credential would
 * invalidate its signature and would test WP_062a instead of isolating
 * WP_060 (see the plan's "Test isolation" risk note).
 *
 * - `type-mismatch` replaces `vct` with a reserved, collision-resistant test
 *   URN and recomputes `'vct#integrity'` to match it, so the *only* observed
 *   defect is the type mismatch itself; leaving a stale integrity hash for a
 *   different `vct` would otherwise be a second, confounding defect.
 * - `schema-invalid` removes the required, non-selectively-disclosable
 *   `issuing_country` claim, leaving `vct` and `'vct#integrity'` nominal.
 *
 * Returns an explicit failure (`ok: false`) instead of silently producing the
 * nominal credential when:
 * - the nominal claims are missing a non-empty string `vct` to mutate, or the
 *   nominal `vct` already equals the reserved mismatch URN (`type-mismatch`);
 * - the nominal claims do not contain `issuing_country` to omit
 *   (`schema-invalid`).
 */
export function applyDigitalCredentialClaimsFault(
  input: ApplyDigitalCredentialClaimsFaultInput
): ApplyDigitalCredentialClaimsFaultResult {
  const { claims, profile } = input;

  if (profile.variant === 'type-mismatch') {
    const expectedVct = claims['vct'];
    if (typeof expectedVct !== 'string' || expectedVct.trim() === '') {
      return {
        ok: false,
        reason: 'Nominal claims are missing a non-empty string vct to mutate for the type-mismatch variant.'
      };
    }
    if (expectedVct === WP_060_TYPE_MISMATCH_VCT) {
      return {
        ok: false,
        reason: 'Nominal vct already equals the reserved type-mismatch test URN; refusing to no-op.'
      };
    }

    return {
      ok: true,
      mutation: {
        claims: {
          ...claims,
          vct: WP_060_TYPE_MISMATCH_VCT,
          'vct#integrity': createSRIHash(WP_060_TYPE_MISMATCH_VCT)
        },
        evidence: { variant: 'type-mismatch', expectedVct, injectedVct: WP_060_TYPE_MISMATCH_VCT }
      }
    };
  }

  if (profile.variant === 'schema-invalid') {
    if (!(WP_060_OMITTED_SCHEMA_CLAIM in claims)) {
      return {
        ok: false,
        reason: `Nominal claims do not contain ${WP_060_OMITTED_SCHEMA_CLAIM}; nothing to omit for the schema-invalid variant.`
      };
    }

    const mutatedClaims = { ...claims };
    delete mutatedClaims[WP_060_OMITTED_SCHEMA_CLAIM];

    return {
      ok: true,
      mutation: {
        claims: mutatedClaims,
        evidence: { variant: 'schema-invalid', omittedClaim: WP_060_OMITTED_SCHEMA_CLAIM }
      }
    };
  }

  const unsupportedVariant: never = profile.variant;
  return {
    ok: false,
    reason: `Unsupported digital-credential-claims-invalid variant: ${String(unsupportedVariant)}`
  };
}
