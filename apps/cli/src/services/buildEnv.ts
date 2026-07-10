import type { ConfigSchemaType } from '@itw-conformance-tool/config';

/**
 * Builds the environment variables for the Nx CLI based on the provided configuration.
 */
export function buildEnv(config: ConfigSchemaType) {
  const keysToAdd = {
    ITW_CT_DATA_DIR: config.global.data_dir,
    ITW_CT_LOG_LEVEL: config.global.log_level,
    ITW_CT_HTTPS: String(config['global'].https),
    ITW_CT_ISSUER_BASE_URL: `https://127.0.0.1:${config['itw-credential-issuer'].port}`,
    ITW_CT_ISSUER_CREDENTIAL_TYPES: String(config['itw-credential-issuer'].credential_types),
    ITW_CT_RP_BASE_URL: `https://127.0.0.1:${config.rp.port}`,
    ITW_CT_ISSUER_AUTH_FLOW: String(config['itw-credential-issuer'].auth_flow),
    ITW_CT_RP_TRUST_ANCHOR_URL: String(config.rp.trust_anchor_url),
    ITW_CT_WALLET_PROVIDER_BACKEND_URL: String(config.global.wallet_provider_backend_url)
  };

  return { ...process.env, ...keysToAdd };
}
