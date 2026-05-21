import type { CLIFlags } from '../types/types.js';

/** Builds the command-line arguments for starting
 * the Nx CLI based on the provided flags.
 *
 * @param flags - The command-line flags that determine which services to start (e.g., all, issuer, rp).
 * @returns An array of strings representing the command-line arguments for the Nx CLI.
 */
export function getNxCommands(flags: CLIFlags): string[] {
  const startAll = flags.all || (flags.issuer && flags.rp) || (!flags.issuer && !flags.rp);

  if (startAll) {
    return ['run-many', '-t', 'serve', '-p', 'itw-credential-issuer,itw-relying-party'];
  }

  if (flags.issuer) {
    return ['run', 'itw-credential-issuer:serve'];
  }

  return ['run', 'itw-relying-party:serve'];
}
