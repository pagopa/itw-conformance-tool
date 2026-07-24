import { issuerFaultProfileSchema, type IssuerFaultProfileType } from './issuer-fault-profile.js';

/**
 * IT Wallet specification versions this catalog can reason about. Kept as
 * plain string literals (matching the `X-Spec-Version` header values used
 * across the Credential Issuer, see `spec-version.ts`) instead of importing
 * `@pagopa/io-wallet-utils`, so this package stays dependency-light.
 */
export const supportedItWalletSpecVersions = ['1.0', '1.3', '1.4'] as const;

export type SupportedItWalletSpecVersion = (typeof supportedItWalletSpecVersions)[number];

export function isSupportedItWalletSpecVersion(value: string): value is SupportedItWalletSpecVersion {
  return (supportedItWalletSpecVersions as readonly string[]).includes(value);
}

/** Where in the Credential Issuer response pipeline a fault profile mutates data. */
export type IssuerFaultApplicationPoint =
  | 'entity-configuration'
  | 'credential-offer'
  | 'federation-artifact'
  | 'authorization-response'
  | 'edc-claims'
  | 'edc-header'
  | 'edc-serialization'
  | 'mdl-serialization';

/** Whether the mutation happens on unsigned claims, or on an already-serialized artifact. */
export type IssuerFaultMutationTiming = 'pre-signature' | 'post-serialization';

export interface IssuerFaultCatalogEntry {
  readonly type: IssuerFaultProfileType;
  readonly applicationPoint: IssuerFaultApplicationPoint;
  readonly supportedSpecVersions: readonly SupportedItWalletSpecVersion[];
  readonly mutationTiming: IssuerFaultMutationTiming;
  /** Whether the current Credential Issuer implements this profile's mutation. */
  readonly implemented: boolean;
}

const ALL_SPEC_VERSIONS = supportedItWalletSpecVersions;

/**
 * Associates every catalogued fault `type` with its application point,
 * supported specification versions, mutation timing, and implementation
 * status. Only entries whose Credential Issuer mutation is wired should be
 * marked `implemented: true`; the remaining entries are reserved metadata so
 * the runner, IPC protocol, and CLI can already validate and reject
 * activation requests for profiles that have no mutation yet.
 */
export const issuerFaultCatalog: Readonly<Record<IssuerFaultProfileType, IssuerFaultCatalogEntry>> = {
  'invalid-trust-anchor': {
    type: 'invalid-trust-anchor',
    applicationPoint: 'entity-configuration',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'unsupported-credential-offer': {
    type: 'unsupported-credential-offer',
    applicationPoint: 'credential-offer',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: false
  },
  'invalid-policy-or-trust-mark': {
    type: 'invalid-policy-or-trust-mark',
    applicationPoint: 'federation-artifact',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: false
  },
  'authorization-response-missing-claim': {
    type: 'authorization-response-missing-claim',
    applicationPoint: 'authorization-response',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'authorization-response-invalid-state': {
    type: 'authorization-response-invalid-state',
    applicationPoint: 'authorization-response',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'authorization-response-invalid-issuer': {
    type: 'authorization-response-invalid-issuer',
    applicationPoint: 'authorization-response',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: false
  },
  'edc-missing-required-claims': {
    type: 'edc-missing-required-claims',
    applicationPoint: 'edc-claims',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: false
  },
  'edc-invalid-trust-chain': {
    type: 'edc-invalid-trust-chain',
    applicationPoint: 'edc-claims',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: false
  },
  'edc-invalid-signature': {
    type: 'edc-invalid-signature',
    applicationPoint: 'edc-serialization',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'post-serialization',
    implemented: false
  },
  'mdl-invalid-signature': {
    type: 'mdl-invalid-signature',
    applicationPoint: 'mdl-serialization',
    supportedSpecVersions: ALL_SPEC_VERSIONS,
    mutationTiming: 'post-serialization',
    implemented: false
  }
};

export function getIssuerFaultCatalogEntry(type: IssuerFaultProfileType): IssuerFaultCatalogEntry {
  return issuerFaultCatalog[type];
}

export type IssuerFaultValidationFailureCode =
  'UNKNOWN_FAULT_PROFILE' | 'FAULT_NOT_IMPLEMENTED' | 'UNSUPPORTED_SPEC_VERSION' | 'INVALID_FAULT_PARAMETERS';

export interface IssuerFaultValidationFailure {
  readonly ok: false;
  readonly code: IssuerFaultValidationFailureCode;
  readonly message: string;
}

export interface IssuerFaultValidationSuccess {
  readonly ok: true;
  readonly catalogEntry: IssuerFaultCatalogEntry;
}

export type IssuerFaultValidationResult = IssuerFaultValidationFailure | IssuerFaultValidationSuccess;

/**
 * Validates an activation request's profile shape, catalog membership,
 * implementation status, and requested specification version in one place,
 * so the Credential Issuer's fault store and any future consumer share
 * identical activation rules instead of re-deriving them.
 */
export function validateIssuerFaultActivation(input: {
  profile: unknown;
  specVersion: string;
}): IssuerFaultValidationResult {
  const parsed = issuerFaultProfileSchema.safeParse(input.profile);
  if (!parsed.success) {
    return {
      ok: false,
      code: 'INVALID_FAULT_PARAMETERS',
      message: `Invalid issuer fault profile: ${parsed.error.message}`
    };
  }

  const catalogEntry = getIssuerFaultCatalogEntry(parsed.data.type);
  if (!catalogEntry.implemented) {
    return {
      ok: false,
      code: 'FAULT_NOT_IMPLEMENTED',
      message: `Issuer fault profile '${parsed.data.type}' is catalogued but not implemented by this Credential Issuer.`
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
      message: `Issuer fault profile '${parsed.data.type}' does not support specification version ${input.specVersion}.`
    };
  }

  return { ok: true, catalogEntry };
}
