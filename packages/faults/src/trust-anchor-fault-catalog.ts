import { isSupportedItWalletSpecVersion, type SupportedItWalletSpecVersion } from './issuer-fault-catalog.js';
import { trustAnchorFaultProfileSchema, type TrustAnchorFaultProfileType } from './trust-anchor-fault-profile.js';

/** Where in the Trust Anchor response pipeline a fault profile mutates data. */
export type TrustAnchorFaultApplicationPoint = 'entity-configuration';

/** Whether the mutation happens on unsigned claims before the entity statement is signed. */
export type TrustAnchorFaultMutationTiming = 'pre-signature';

export interface TrustAnchorFaultCatalogEntry {
  readonly type: TrustAnchorFaultProfileType;
  readonly applicationPoint: TrustAnchorFaultApplicationPoint;
  readonly supportedSpecVersions: readonly SupportedItWalletSpecVersion[];
  readonly mutationTiming: TrustAnchorFaultMutationTiming;
  /** Whether the current Trust Anchor implements this profile's mutation. */
  readonly implemented: boolean;
}

const TRUST_ANCHOR_FAULT_TESTED_SPEC_VERSIONS = ['1.4'] as const satisfies readonly SupportedItWalletSpecVersion[];

export const trustAnchorFaultCatalog: Readonly<Record<TrustAnchorFaultProfileType, TrustAnchorFaultCatalogEntry>> = {
  'entity-configuration-nonmatching-signing-key': {
    type: 'entity-configuration-nonmatching-signing-key',
    applicationPoint: 'entity-configuration',
    supportedSpecVersions: TRUST_ANCHOR_FAULT_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  }
};

export function getTrustAnchorFaultCatalogEntry(type: TrustAnchorFaultProfileType): TrustAnchorFaultCatalogEntry {
  return trustAnchorFaultCatalog[type];
}

export type TrustAnchorFaultValidationFailureCode =
  'UNKNOWN_FAULT_PROFILE' | 'FAULT_NOT_IMPLEMENTED' | 'UNSUPPORTED_SPEC_VERSION' | 'INVALID_FAULT_PARAMETERS';

export interface TrustAnchorFaultValidationFailure {
  readonly ok: false;
  readonly code: TrustAnchorFaultValidationFailureCode;
  readonly message: string;
}

export interface TrustAnchorFaultValidationSuccess {
  readonly ok: true;
  readonly catalogEntry: TrustAnchorFaultCatalogEntry;
}

export type TrustAnchorFaultValidationResult = TrustAnchorFaultValidationFailure | TrustAnchorFaultValidationSuccess;

/**
 * Validates an activation request's profile shape, catalog membership,
 * implementation status, and requested specification version in one place.
 */
export function validateTrustAnchorFaultActivation(input: {
  profile: unknown;
  specVersion: string;
}): TrustAnchorFaultValidationResult {
  const parsed = trustAnchorFaultProfileSchema.safeParse(input.profile);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'INVALID_FAULT_PARAMETERS',
      message: `Invalid Trust Anchor fault profile: ${parsed.error.message}`
    };
  }

  const catalogEntry = getTrustAnchorFaultCatalogEntry(parsed.data.type);
  if (!catalogEntry.implemented) {
    return {
      ok: false,
      code: 'FAULT_NOT_IMPLEMENTED',
      message: `Trust Anchor fault profile '${parsed.data.type}' is catalogued but not implemented by this Trust Anchor.`
    };
  }

  if (!isSupportedItWalletSpecVersion(input.specVersion)) {
    return {
      ok: false,
      code: 'UNSUPPORTED_SPEC_VERSION',
      message: `Unsupported IT Wallet specification version: ${input.specVersion}`
    };
  }

  if (!catalogEntry.supportedSpecVersions.includes(input.specVersion)) {
    return {
      ok: false,
      code: 'UNSUPPORTED_SPEC_VERSION',
      message: `Trust Anchor fault profile '${parsed.data.type}' does not support specification version ${input.specVersion}.`
    };
  }

  return { ok: true, catalogEntry };
}
