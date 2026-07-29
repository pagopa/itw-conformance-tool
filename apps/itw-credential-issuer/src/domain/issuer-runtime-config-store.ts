export interface IssuerRuntimeConfig {
  batchIssuanceByDeferred: boolean;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  statusList?: {
    bits: 4;
    values: number[];
  };
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
  resolveAccessTokenTtlSeconds(staticValue: number): number;
  resolveRefreshTokenTtlSeconds(staticValue: number): number;
  resolveStatusList<T extends { bits: number; values: number[] }>(staticValue: T): T;
  clear(): void;
}

function isValidConfig(config: IssuerRuntimeConfig): boolean {
  return (
    typeof config.batchIssuanceByDeferred === 'boolean' &&
    isValidOptionalPositiveInteger(config.accessTokenTtlSeconds) &&
    isValidOptionalPositiveInteger(config.refreshTokenTtlSeconds) &&
    isValidStatusListConfig(config.statusList)
  );
}

function isValidOptionalPositiveInteger(value: number | undefined): boolean {
  return value === undefined || (Number.isInteger(value) && value > 0);
}

function isValidStatusListConfig(config: IssuerRuntimeConfig['statusList']): boolean {
  if (config === undefined) return true;
  if (config.bits !== 4) return false;
  if (!Array.isArray(config.values) || config.values.length === 0) return false;

  const maxValue = 2 ** config.bits - 1;
  return config.values.every((value) => Number.isInteger(value) && value >= 0 && value <= maxValue);
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
    resolveAccessTokenTtlSeconds(staticValue) {
      return active?.config.accessTokenTtlSeconds ?? staticValue;
    },
    resolveRefreshTokenTtlSeconds(staticValue) {
      return active?.config.refreshTokenTtlSeconds ?? staticValue;
    },
    resolveStatusList(staticValue) {
      const override = active?.config.statusList;
      if (!override) return staticValue;

      return {
        bits: override.bits,
        values: [...override.values]
      } as typeof staticValue;
    },
    clear() {
      active = undefined;
    }
  };
}
