import {
  validateIssuerFaultActivation,
  type IssuerFaultCatalogEntry,
  type IssuerFaultProfile
} from '@itw-conformance-tool/faults';

/** A currently-active issuer fault, plus the metadata needed to enforce ownership and report evidence. */
export interface ActiveIssuerFault {
  readonly scenarioId: string;
  readonly specVersion: string;
  readonly profile: IssuerFaultProfile;
  readonly catalogEntry: IssuerFaultCatalogEntry;
  readonly activatedAt: string;
}

export interface ActivateIssuerFaultInput {
  scenarioId: string;
  specVersion: string;
  profile: unknown;
}

export interface DeactivateIssuerFaultInput {
  scenarioId: string;
}

export type IssuerFaultStoreFailureCode =
  | 'FAULT_ALREADY_ACTIVE'
  | 'FAULT_OWNERSHIP_MISMATCH'
  | 'UNKNOWN_FAULT_PROFILE'
  | 'INVALID_FAULT_PARAMETERS'
  | 'FAULT_NOT_IMPLEMENTED'
  | 'UNSUPPORTED_SPEC_VERSION';

export interface IssuerFaultStoreFailure {
  readonly ok: false;
  readonly code: IssuerFaultStoreFailureCode;
  readonly message: string;
}

export interface IssuerFaultStoreSuccess {
  readonly ok: true;
}

export type IssuerFaultStoreResult = IssuerFaultStoreFailure | IssuerFaultStoreSuccess;

/**
 * Single-active-fault, ownership-aware in-memory store for Credential Issuer
 * fault activation state. One instance is created per application process
 * (see `plugins/issuer-faults.ts`) and shared between the IPC handlers
 * (activate/deactivate) and the response builders that need to read the
 * currently active fault (e.g. `routes/federation.ts`).
 */
export interface IssuerFaultStore {
  /**
   * Activates a fault profile after validating it against the fault catalog.
   * Rejects activation if a different scenario already owns an active fault;
   * re-activating with the same `scenarioId` overwrites the existing state.
   */
  activate(input: ActivateIssuerFaultInput): IssuerFaultStoreResult;
  /**
   * Idempotent for the owning scenario: deactivating when nothing is active
   * succeeds as a no-op. Deactivating a fault owned by a different
   * `scenarioId` is rejected instead of silently clearing someone else's
   * fault.
   */
  deactivate(input: DeactivateIssuerFaultInput): IssuerFaultStoreResult;
  /** Narrow read API for response builders: the active fault, or `undefined`. */
  getActive(): ActiveIssuerFault | undefined;
  /** Clears any active fault without ownership checks. Used on application close. */
  clear(): void;
}

export function createIssuerFaultStore(): IssuerFaultStore {
  let active: ActiveIssuerFault | undefined;

  return {
    activate(input) {
      if (active && active.scenarioId !== input.scenarioId) {
        return {
          ok: false,
          code: 'FAULT_ALREADY_ACTIVE',
          message: `An issuer fault is already active for scenario '${active.scenarioId}'.`
        };
      }

      const validation = validateIssuerFaultActivation({ profile: input.profile, specVersion: input.specVersion });
      if (!validation.ok) {
        return { ok: false, code: validation.code, message: validation.message };
      }

      active = {
        scenarioId: input.scenarioId,
        specVersion: input.specVersion,
        profile: input.profile as IssuerFaultProfile,
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
          message: `Scenario '${input.scenarioId}' does not own the active issuer fault ('${active.scenarioId}').`
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
