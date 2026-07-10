import type { ConfigSchemaType } from '@itw-conformance-tool/config';

/**
 * Builds the environment variables for the Nx CLI based on the provided configuration.
 */
export function buildEnv(configs: ConfigSchemaType) {
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
    ITW_CT_WALLET_PROVIDER_BACKEND_URL: String(configs.global.wallet_provider_backend_url)
  };

  return { ...process.env, ...keysToAdd };
}
