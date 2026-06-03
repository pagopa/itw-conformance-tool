import type { CLIFlags, ServiceProcess } from '../types/types.js';

const ISSUER: ServiceProcess = {
  prefix: 'itw-credential-issuer',
  nxArgs: ['run', 'itw-credential-issuer:serve']
};

const RP: ServiceProcess = {
  prefix: 'itw-relying-party',
  nxArgs: ['run', 'itw-relying-party:serve']
};

/** Builds the list of service processes to start based on the provided flags.
 * Each entry carries the output prefix and the Nx CLI arguments for that service.
 *
 * @param flags - The command-line flags that determine which services to start.
 * @returns An array of ServiceProcess descriptors, one per service to launch.
 */
export function getNxCommands(flags: CLIFlags): ServiceProcess[] {
  const startAll = flags.all || (flags.issuer && flags.rp) || (!flags.issuer && !flags.rp);
  if (startAll) return [ISSUER, RP];
  if (flags.issuer) return [ISSUER];
  return [RP];
}
