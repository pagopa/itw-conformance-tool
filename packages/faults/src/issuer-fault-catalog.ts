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
  | 'mdl-serialization'
  | 'credential-response';

/**
 * Whether the mutation happens on unsigned claims, on an already-serialized
 * artifact, or on the unsigned Credential Response wrapper after the SDK has
 * built it (`post-build`). The Credential Response is not itself a signed
 * artifact, so mutating it does not fit `pre-signature`/`post-serialization`.
 */
export type IssuerFaultMutationTiming = 'pre-signature' | 'post-serialization' | 'post-build';

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
 * Specification versions verified for the `edc-missing-required-claims`
 * Credential Response mutation. The immediate response shape is documented
 * as identical across all supported versions, but this increment's WP_059
 * scenario and matrix test only exercise `1.4`; widen this list only once
 * `1.0` and `1.3` have their own verified test coverage.
 */
const CREDENTIAL_RESPONSE_TESTED_SPEC_VERSIONS = ['1.4'] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Specification versions verified for the `digital-credential-claims-invalid`
 * (WP_060) pre-signature mutation. Limited to `1.4`, the version targeted by
 * this increment's scenario and matrix test, until `1.0` and `1.3` have their
 * own verified fixtures; see the plan's "Version drift" risk note.
 */
const DIGITAL_CREDENTIAL_CLAIMS_TESTED_SPEC_VERSIONS = [
  '1.4'
] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Specification versions verified for the `edc-invalid-trust-chain` (WP_061)
 * pre-signature Digital Credential header mutation. Limited to `1.4`, the
 * version targeted by this increment's scenario and matrix test, until `1.0`
 * and `1.3` have their own verified fixtures; see the plan's "Version drift"
 * risk note.
 */
const EDC_INVALID_TRUST_CHAIN_TESTED_SPEC_VERSIONS = ['1.4'] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Specification versions verified for the `edc-invalid-signature` (WP_062a)
 * post-serialization Digital Credential signature mutation. Limited to `1.4`,
 * the version targeted by this increment's scenario and matrix test, until
 * `1.0` and `1.3` have their own verified fixtures; see the plan's "Version
 * drift" risk note.
 */
const EDC_INVALID_SIGNATURE_TESTED_SPEC_VERSIONS = ['1.4'] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Specification versions verified for the `mdl-invalid-signature` (WP_062b)
 * post-serialization mdoc-CBOR signature mutation. Limited to `1.4`, the
 * version targeted by this increment's scenario and matrix test, until
 * `1.0` and `1.3` have their own verified fixtures; see the plan's "Version
 * drift" risk note.
 */
const MDL_INVALID_SIGNATURE_TESTED_SPEC_VERSIONS = ['1.4'] as const satisfies readonly SupportedItWalletSpecVersion[];

/**
 * Associates every catalogued fault `type` with its application point,
 * supported specification versions, mutation timing, and implementation
 * status. `invalid-trust-anchor`, `unsupported-credential-offer`,
 * `edc-missing-required-claims`, `digital-credential-claims-invalid`, and
 * `edc-invalid-trust-chain`, `edc-invalid-signature`, and
 * `mdl-invalid-signature` are `implemented: true`; every other entry is
 * reserved metadata so the runner, IPC protocol, and CLI can already
 * validate and reject activation requests for profiles that have no mutation
 * yet.
 *
 * `unsupported-credential-offer`'s application point is `credential-offer`,
 * but unlike the other profiles it is not mutated by a Credential Issuer
 * HTTP response: for interactive scenarios the Credential Offer is built by
 * the conformance runner itself (see `helpers/issuance.ts` and
 * `runner/scenario-runner.ts` in `@itw-conformance-tool/conformance`), which
 * applies the mutation after activation is acknowledged, acting as the third
 * party that presents the offer to the wallet.
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
    implemented: true
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
    implemented: true
  },
  'edc-missing-required-claims': {
    type: 'edc-missing-required-claims',
    applicationPoint: 'credential-response',
    supportedSpecVersions: CREDENTIAL_RESPONSE_TESTED_SPEC_VERSIONS,
    mutationTiming: 'post-build',
    implemented: true
  },
  'edc-invalid-trust-chain': {
    type: 'edc-invalid-trust-chain',
    applicationPoint: 'edc-header',
    supportedSpecVersions: EDC_INVALID_TRUST_CHAIN_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
  },
  'edc-invalid-signature': {
    type: 'edc-invalid-signature',
    applicationPoint: 'edc-serialization',
    supportedSpecVersions: EDC_INVALID_SIGNATURE_TESTED_SPEC_VERSIONS,
    mutationTiming: 'post-serialization',
    implemented: true
  },
  'mdl-invalid-signature': {
    type: 'mdl-invalid-signature',
    applicationPoint: 'mdl-serialization',
    supportedSpecVersions: MDL_INVALID_SIGNATURE_TESTED_SPEC_VERSIONS,
    mutationTiming: 'post-serialization',
    implemented: true
  },
  'digital-credential-claims-invalid': {
    type: 'digital-credential-claims-invalid',
    applicationPoint: 'edc-claims',
    supportedSpecVersions: DIGITAL_CREDENTIAL_CLAIMS_TESTED_SPEC_VERSIONS,
    mutationTiming: 'pre-signature',
    implemented: true
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
