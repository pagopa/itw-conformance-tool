import { resolve } from 'node:path';

import type { LogLevel } from '../types/types.js';
import type { ConfigType } from '@itw-conformance-tool/config';

/** Builds the environment variables for the Nx CLI based on the provided configuration.
 *
 * @param configs - The configuration object containing the necessary values for the environment variables.
 * @param emitLog - A function to emit log messages.
 * @param configFilePath - Absolute path to the config.ini file, forwarded to child processes.
 * @returns An object containing the environment variables for the Nx CLI.
 */
export function buildEnv(
  configs: ConfigType,
  emitLog: (event: string, type?: LogLevel) => void,
  configFilePath?: string
) {
  const keysToAdd = {
    ITW_CT_DATA_DIR: configs.global.data_dir,
    ITW_CT_LOG_LEVEL: configs.global.log_level,
    ITW_CT_HTTPS: String(configs['global'].https),
    ITW_CT_ISSUER_PORT: String(configs['itw-credential-issuer'].port),
    ITW_CT_ISSUER_CREDENTIAL_TYPES: String(configs['itw-credential-issuer'].credential_types),
    ITW_CT_RP_PORT: String(configs.rp.port),
    ITW_CT_RP_BASE_URL: `https://127.0.0.1:${configs.rp.port}`,
    ITW_CT_ISSUER_AUTH_FLOW: String(configs['itw-credential-issuer'].auth_flow),
    ITW_CT_RP_TRUST_ANCHOR_URL: String(configs.rp.trust_anchor_url),
    ITW_CT_WALLET_PROVIDER_BACKEND_URL: String(configs.global.wallet_provider_backend_url),
    ITW_CT_CONFIG_FILE: configFilePath ?? resolve(process.cwd(), 'config.ini')
  };

  emitLog(`\nEnvironment variables for Nx CLI:\n${JSON.stringify(keysToAdd, null, 2)}\n`);

  return { ...process.env, ...keysToAdd };
}
