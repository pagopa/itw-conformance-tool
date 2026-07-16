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
 * Builds the list of service processes to start based on the provided flags.
 * Each entry carries the output prefix and the Nx CLI arguments for that service.
 *
 * @param flags - The parsed CLI flags.
 */
export function getNxCommands(flags: CliFlags): ServiceProcess[] {
  if (flags.all) return [TRUST_ANCHOR, ISSUER, RP];
  if (flags.issuer) return [ISSUER];
  if (flags.rp) return [RP];
  if (flags.trustAnchor) return [TRUST_ANCHOR];

  throw new Error('No services specified to start. Use --all, --issuer, --rp, or --trust-anchor.');
}
