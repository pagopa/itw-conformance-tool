export interface IssuerRuntimeConfig {
  batchIssuanceByDeferred: boolean;
}

export interface ActiveIssuerRuntimeConfig {
  readonly scenarioId: string;
  readonly config: IssuerRuntimeConfig;
  readonly activatedAt: string;
}

export interface ActivateIssuerRuntimeConfigInput {
  scenarioId: string;
  config: IssuerRuntimeConfig;
}

export interface DeactivateIssuerRuntimeConfigInput {
  scenarioId: string;
}

export type IssuerRuntimeConfigStoreFailureCode =
  'CONFIG_ALREADY_ACTIVE' | 'CONFIG_OWNERSHIP_MISMATCH' | 'INVALID_CONFIG';

export interface IssuerRuntimeConfigStoreFailure {
  readonly ok: false;
  readonly code: IssuerRuntimeConfigStoreFailureCode;
  readonly message: string;
}

export interface IssuerRuntimeConfigStoreSuccess {
  readonly ok: true;
}

export type IssuerRuntimeConfigStoreResult = IssuerRuntimeConfigStoreFailure | IssuerRuntimeConfigStoreSuccess;

export interface IssuerRuntimeConfigStore {
  activate(input: ActivateIssuerRuntimeConfigInput): IssuerRuntimeConfigStoreResult;
  deactivate(input: DeactivateIssuerRuntimeConfigInput): IssuerRuntimeConfigStoreResult;
  getActive(): ActiveIssuerRuntimeConfig | undefined;
  resolveBatchIssuanceByDeferred(staticValue: boolean): boolean;
  clear(): void;
}

function isValidConfig(config: IssuerRuntimeConfig): boolean {
  return typeof config.batchIssuanceByDeferred === 'boolean';
}

export function createIssuerRuntimeConfigStore(): IssuerRuntimeConfigStore {
  let active: ActiveIssuerRuntimeConfig | undefined;

  return {
    activate(input) {
      if (!isValidConfig(input.config)) {
        return {
          ok: false,
          code: 'INVALID_CONFIG',
          message: 'Issuer runtime config override is invalid.'
        };
      }

      if (active && active.scenarioId !== input.scenarioId) {
        return {
          ok: false,
          code: 'CONFIG_ALREADY_ACTIVE',
          message: `An issuer runtime config override is already active for scenario '${active.scenarioId}'.`
        };
      }

      active = {
        scenarioId: input.scenarioId,
        config: input.config,
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
          code: 'CONFIG_OWNERSHIP_MISMATCH',
          message: `Scenario '${input.scenarioId}' does not own the active issuer runtime config override ('${active.scenarioId}').`
        };
      }

      active = undefined;
      return { ok: true };
    },
    getActive() {
      return active;
    },
    resolveBatchIssuanceByDeferred(staticValue) {
      return active?.config.batchIssuanceByDeferred ?? staticValue;
    },
    clear() {
      active = undefined;
    }
  };
}
