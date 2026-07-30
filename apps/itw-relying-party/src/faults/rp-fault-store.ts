import { validateRpFaultActivation, type RpFaultCatalogEntry, type RpFaultProfile } from '@itw-conformance-tool/faults';

/** A currently-active relying party fault, plus the metadata needed to enforce ownership and report evidence. */
export interface ActiveRpFault {
  readonly scenarioId: string;
  readonly specVersion: string;
  readonly profile: RpFaultProfile;
  readonly catalogEntry: RpFaultCatalogEntry;
  readonly activatedAt: string;
}

export interface ActivateRpFaultInput {
  scenarioId: string;
  specVersion: string;
  profile: unknown;
}

export interface DeactivateRpFaultInput {
  scenarioId: string;
}

export type RpFaultStoreFailureCode =
  | 'FAULT_ALREADY_ACTIVE'
  | 'FAULT_OWNERSHIP_MISMATCH'
  | 'UNKNOWN_FAULT_PROFILE'
  | 'INVALID_FAULT_PARAMETERS'
  | 'FAULT_NOT_IMPLEMENTED'
  | 'UNSUPPORTED_SPEC_VERSION';

export interface RpFaultStoreFailure {
  readonly ok: false;
  readonly code: RpFaultStoreFailureCode;
  readonly message: string;
}

export interface RpFaultStoreSuccess {
  readonly ok: true;
}

export type RpFaultStoreResult = RpFaultStoreFailure | RpFaultStoreSuccess;

/**
 * Single-active-fault, ownership-aware in-memory store for Relying Party fault
 * activation state. One instance is created per application process (see
 * `plugins/rp-faults.ts`) and shared between the IPC handlers
 * (activate/deactivate) and the response builders that need to read the
 * currently active fault (e.g. `handlers/create-entity-configuration.ts`).
 * Mirrors the Credential Issuer's `IssuerFaultStore`.
 */
export interface RpFaultStore {
  /**
   * Activates a fault profile after validating it against the fault catalog.
   * Rejects activation if a different scenario already owns an active fault;
   * re-activating with the same `scenarioId` overwrites the existing state.
   */
  activate(input: ActivateRpFaultInput): RpFaultStoreResult;
  /**
   * Idempotent for the owning scenario: deactivating when nothing is active
   * succeeds as a no-op. Deactivating a fault owned by a different
   * `scenarioId` is rejected instead of silently clearing someone else's
   * fault.
   */
  deactivate(input: DeactivateRpFaultInput): RpFaultStoreResult;
  /** Narrow read API for response builders: the active fault, or `undefined`. */
  getActive(): ActiveRpFault | undefined;
  /** Clears any active fault without ownership checks. Used on application close. */
  clear(): void;
}

export function createRpFaultStore(): RpFaultStore {
  let active: ActiveRpFault | undefined;

  return {
    activate(input) {
      if (active && active.scenarioId !== input.scenarioId) {
        return {
          ok: false,
          code: 'FAULT_ALREADY_ACTIVE',
          message: `A relying party fault is already active for scenario '${active.scenarioId}'.`
        };
      }

      const validation = validateRpFaultActivation({ profile: input.profile, specVersion: input.specVersion });
      if (!validation.ok) {
        return { ok: false, code: validation.code, message: validation.message };
      }

      active = {
        scenarioId: input.scenarioId,
        specVersion: input.specVersion,
        profile: input.profile as RpFaultProfile,
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
          message: `Scenario '${input.scenarioId}' does not own the active relying party fault ('${active.scenarioId}').`
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
