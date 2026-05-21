import { spawn } from 'node:child_process';

import { searchNx } from '../utils/search.js';

/** Runs the specified Nx CLI commands as a child process,
 * inheriting the standard input/output streams and using the
 * provided environment variables.
 *
 * @param rootPath - The root directory of the project.
 * @param nxArgs - The arguments to pass to the Nx CLI.
 * @param env - The environment variables to use for the child process.
 * @returns A promise that resolves with the exit code of the child process.
 */
export async function runCommands(rootPath: string, nxArgs: string[], env: NodeJS.ProcessEnv): Promise<number> {
  const nxCliPath = searchNx(rootPath);

  return new Promise<number>((resolveExitCode, reject) => {
    const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
      stdio: 'inherit',
      cwd: rootPath,
      env
    });

    child.once('error', reject);
    child.once('close', (code) => {
      resolveExitCode(code ?? 1);
    });
  });
}
