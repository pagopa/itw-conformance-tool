import type { CliFlags, ServiceProcess } from '../types/types.js';

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
 */
export function getNxCommands(flags: CliFlags): ServiceProcess[] {
  if (flags.all) return [ISSUER, RP];
  if (flags.issuer) return [ISSUER];
  if (flags.rp) return [RP];

  throw new Error('No services specified to start. Use --all, --issuer, or --rp.');
}
