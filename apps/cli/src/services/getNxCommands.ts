import type { CliFlags, ServiceProcess } from '../types/types.js';

const TRUST_ANCHOR: ServiceProcess = {
  prefix: 'itw-trust-anchor',
  nxArgs: ['run', 'itw-trust-anchor:serve']
};

const ISSUER: ServiceProcess = {
  prefix: 'itw-credential-issuer',
  nxArgs: ['run', 'itw-credential-issuer:serve']
};

const RP: ServiceProcess = {
  prefix: 'itw-relying-party',
  nxArgs: ['run', 'itw-relying-party:serve']
};

/**
 * Builds the env overrides forwarded to the issuer child process only: the
 * resolved config file path (so the issuer honours the same `--config`
 * selection as the CLI, regardless of the child's working directory) and the
 * `--credential-identifiers` override, if provided.
 */
function buildIssuerEnv(flags: CliFlags, configFilePath: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ITW_CONFIG_PATH: configFilePath };

  if (flags.credentialIdentifiers && flags.credentialIdentifiers.length > 0) {
    env.ITW_CREDENTIAL_IDENTIFIERS = flags.credentialIdentifiers.join(',');
  }

  return env;
}

/**
 * Builds the list of service processes to start based on the provided flags.
 * Each entry carries the output prefix and the Nx CLI arguments for that service.
 *
 * @param flags - The parsed CLI flags.
 * @param configFilePath - The resolved config file path, forwarded only to the issuer child.
 */
export function getNxCommands(flags: CliFlags, configFilePath: string): ServiceProcess[] {
  const issuer: ServiceProcess = { ...ISSUER, env: buildIssuerEnv(flags, configFilePath) };

  if (flags.all) return [TRUST_ANCHOR, issuer, RP];
  if (flags.issuer) return [issuer];
  if (flags.rp) return [RP];
  if (flags.trustAnchor) return [TRUST_ANCHOR];

  throw new Error('No services specified to start. Use --all, --issuer, --rp, or --trust-anchor.');
}
