import type { LogLevel } from '../types/types.js';
import type { ConfigType } from '@itw-conformance-tool/config';

/** Builds the environment variables for the Nx CLI based on the provided configuration.
 *
 * @param configs - The configuration object containing the necessary values for the environment variables.
 * @param emitLog - A function to emit log messages.
 * @returns An object containing the environment variables for the Nx CLI.
 */
export function buildEnv(configs: ConfigType, emitLog: (event: string, type?: LogLevel) => void) {
  const keysToAdd = {
    ITW_CT_DATA_DIR: configs.global.data_dir,
    ITW_CT_LOG_LEVEL: configs.global.log_level,
    ITW_CT_HTTPS: String(configs['global'].https),
    ITW_CT_ISSUER_PORT: String(configs['itw-credential-issuer'].port),
    ITW_CT_ISSUER_CREDENTIAL_TYPES: String(configs['itw-credential-issuer'].credential_types),
    ITW_CT_RP_PORT: String(configs.rp.port),
    ITW_CT_RP_BASE_URL: String(configs.rp.entity_id),
    ITW_CT_ISSUER_AUTH_FLOW: String(configs['itw-credential-issuer'].auth_flow),
    ITW_CT_RP_TRUST_ANCHOR_URL: String(configs.rp.trust_anchor_url)
  };

  emitLog(`\nEnvironment variables for Nx CLI:\n${JSON.stringify(keysToAdd, null, 2)}\n`);

  return { ...process.env, ...keysToAdd };
}
