import {
  validateTrustAnchorFaultActivation,
  type TrustAnchorFaultCatalogEntry,
  type TrustAnchorFaultProfile
} from '@itw-conformance-tool/faults';

export interface ActiveTrustAnchorFault {
  readonly scenarioId: string;
  readonly specVersion: string;
  readonly profile: TrustAnchorFaultProfile;
  readonly catalogEntry: TrustAnchorFaultCatalogEntry;
  readonly activatedAt: string;
}

export interface ActivateTrustAnchorFaultInput {
  scenarioId: string;
  specVersion: string;
  profile: unknown;
}

export interface DeactivateTrustAnchorFaultInput {
  scenarioId: string;
}

export type TrustAnchorFaultStoreFailureCode =
  | 'FAULT_ALREADY_ACTIVE'
  | 'FAULT_OWNERSHIP_MISMATCH'
  | 'UNKNOWN_FAULT_PROFILE'
  | 'INVALID_FAULT_PARAMETERS'
  | 'FAULT_NOT_IMPLEMENTED'
  | 'UNSUPPORTED_SPEC_VERSION';

export interface TrustAnchorFaultStoreFailure {
  readonly ok: false;
  readonly code: TrustAnchorFaultStoreFailureCode;
  readonly message: string;
}

export interface TrustAnchorFaultStoreSuccess {
  readonly ok: true;
}

export type TrustAnchorFaultStoreResult = TrustAnchorFaultStoreFailure | TrustAnchorFaultStoreSuccess;

export interface TrustAnchorFaultStore {
  activate(input: ActivateTrustAnchorFaultInput): TrustAnchorFaultStoreResult;
  deactivate(input: DeactivateTrustAnchorFaultInput): TrustAnchorFaultStoreResult;
  getActive(): ActiveTrustAnchorFault | undefined;
  clear(): void;
}

export function createTrustAnchorFaultStore(): TrustAnchorFaultStore {
  let active: ActiveTrustAnchorFault | undefined;

  return {
    activate(input) {
      if (active && active.scenarioId !== input.scenarioId) {
        return {
          ok: false,
          code: 'FAULT_ALREADY_ACTIVE',
          message: `A Trust Anchor fault is already active for scenario '${active.scenarioId}'.`
        };
      }

      const validation = validateTrustAnchorFaultActivation({ profile: input.profile, specVersion: input.specVersion });
      if (!validation.ok) {
        return { ok: false, code: validation.code, message: validation.message };
      }

      active = {
        scenarioId: input.scenarioId,
        specVersion: input.specVersion,
        profile: input.profile as TrustAnchorFaultProfile,
        catalogEntry: validation.catalogEntry,
        activatedAt: new Date().toISOString()
      };

      return { ok: true };
    },
    deactivate(input) {
      if (!active) {
        return { ok: true };
      }

      if (active.scenarioId !== input.scenarioId) {
        return {
          ok: false,
          code: 'FAULT_OWNERSHIP_MISMATCH',
          message: `Scenario '${input.scenarioId}' does not own the active Trust Anchor fault ('${active.scenarioId}').`
        };
      }

      active = undefined;
      return { ok: true };
    },
    getActive() {
      return active;
    },
    clear() {
      active = undefined;
    }
  };
}
