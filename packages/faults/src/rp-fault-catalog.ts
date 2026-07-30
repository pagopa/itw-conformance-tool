import { rpFaultProfileSchema, type RpFaultProfileType } from './rp-fault-profile.js';
import { isSupportedItWalletSpecVersion, type SupportedItWalletSpecVersion } from './spec-versions.js';

/** Where in the Relying Party response pipeline a fault profile mutates data. */
export type RpFaultApplicationPoint = 'rp-entity-configuration' | 'rp-request-object';

/**
 * Whether the mutation happens on unsigned claims before signing, or on the
 * signature itself (the artifact is signed with a key no verifier can resolve).
 */
export type RpFaultMutationTiming = 'at-signature' | 'pre-signature';

export interface RpFaultCatalogEntry {
  readonly type: RpFaultProfileType;
  readonly applicationPoint: RpFaultApplicationPoint;
  readonly supportedSpecVersions: readonly SupportedItWalletSpecVersion[];
  readonly mutationTiming: RpFaultMutationTiming;
  /** Whether the current Relying Party implements this profile's mutation. */
  readonly implemented: boolean;
}

/**
 * The local Relying Party is pinned to IT Wallet `1.3` (see
 * `apps/itw-relying-party/src/plugins/sdk.ts`), so every Relying Party fault is
 * verified against that version only. Widen a profile's list once the Relying
 * Party can serve another version and that version has its own verified test
 * coverage.
 */
const RELYING_PARTY_TESTED_SPEC_VERSIONS = ['1.3'] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Associates every catalogued Relying Party fault `type` with its application
 * point, supported specification versions, mutation timing, and implementation
 * status. Every entry is `implemented: true`: unlike the Credential Issuer
 * catalog, this one was introduced together with its mutations, so it carries
 * no reserved metadata. Keep new entries `implemented: false` until the
 * corresponding mutation exists, so the runner, IPC protocol, and CLI can
 * already validate and reject activation requests for them.
 */
export const rpFaultCatalog: Readonly<Record<RpFaultProfileType, RpFaultCatalogEntry>> = {
  'invalid-trust-anchor': {
    type: 'invalid-trust-anchor',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'invalid-trust-mark': {
    type: 'invalid-trust-mark',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'at-signature',
    implemented: true
  },
  'unattested-request-uri': {
    type: 'unattested-request-uri',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'unattested-response-uri': {
    type: 'unattested-response-uri',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'missing-presentation-trust-mark': {
    type: 'missing-presentation-trust-mark',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'request-object-invalid-signature': {
    type: 'request-object-invalid-signature',
    applicationPoint: 'rp-request-object',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'at-signature',
    implemented: true
  },
  'request-object-invalid-client-id': {
    type: 'request-object-invalid-client-id',
    applicationPoint: 'rp-request-object',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'request-object-federation-key': {
    type: 'request-object-federation-key',
    applicationPoint: 'rp-request-object',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    // The header and the `client_id` claim are rewritten before signing; the
    // signature itself stays valid and is produced with the nominal key.
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'request-object-missing-parameter': {
    type: 'request-object-missing-parameter',
    applicationPoint: 'rp-request-object',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'unattested-redirect-uri': {
    type: 'unattested-redirect-uri',
    applicationPoint: 'rp-entity-configuration',
    supportedSpecVersions: RELYING_PARTY_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  }
};

export function getRpFaultCatalogEntry(type: RpFaultProfileType): RpFaultCatalogEntry {
  return rpFaultCatalog[type];
}

export type RpFaultValidationFailureCode =
  'UNKNOWN_FAULT_PROFILE' | 'FAULT_NOT_IMPLEMENTED' | 'UNSUPPORTED_SPEC_VERSION' | 'INVALID_FAULT_PARAMETERS';

export interface RpFaultValidationFailure {
  readonly ok: false;
  readonly code: RpFaultValidationFailureCode;
  readonly message: string;
}

export interface RpFaultValidationSuccess {
  readonly ok: true;
  readonly catalogEntry: RpFaultCatalogEntry;
}

export type RpFaultValidationResult = RpFaultValidationFailure | RpFaultValidationSuccess;

/**
 * Validates an activation request's profile shape, catalog membership,
 * implementation status, and requested specification version in one place, so
 * the Relying Party's fault store and any future consumer share identical
 * activation rules instead of re-deriving them. Mirrors
 * `validateIssuerFaultActivation`.
 */
export function validateRpFaultActivation(input: { profile: unknown; specVersion: string }): RpFaultValidationResult {
  const parsed = rpFaultProfileSchema.safeParse(input.profile);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'INVALID_FAULT_PARAMETERS',
      message: `Invalid relying party fault profile: ${parsed.error.message}`
    };
  }

  const catalogEntry = getRpFaultCatalogEntry(parsed.data.type);
  if (!catalogEntry.implemented) {
    return {
      ok: false,
      code: 'FAULT_NOT_IMPLEMENTED',
      message: `Relying party fault profile '${parsed.data.type}' is catalogued but not implemented by this Relying Party.`
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
      message: `Relying party fault profile '${parsed.data.type}' does not support specification version ${input.specVersion}.`
    };
  }

  return { ok: true, catalogEntry };
}
