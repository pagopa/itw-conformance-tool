import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import { searchNx } from '../utils/search.js';
import type { EmitLog, ServiceProcess } from '../types/types.js';

/** Runs the specified Nx CLI commands for the selected services, 
 * streaming their output in real-time.
 * 
 * @param rootPath - The root directory of the project.
 * @param services - The list of service processes to start.
 * @param env - The environment variables to use for the child processes.
 * @param emitLog - Logger function used to emit prefixed output lines.
 * @returns A promise that resolves to the combined exit code of all processes (0 if all succeed, 1 if any fail).
 */
export async function runCommands(
  rootPath: string,
  services: ServiceProcess[],
  env: NodeJS.ProcessEnv,
  emitLog: EmitLog
): Promise<number> {
  const nxCliPath = searchNx(rootPath);
  const exitCodes = await Promise.all(
    services.map(
      ({ prefix, nxArgs }) =>
        new Promise<number>((resolve, reject) => {
          const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
            stdio: ['inherit', 'pipe', 'pipe'],
            cwd: rootPath,
            env
          });

          const tag = `[${prefix}]`;

          createInterface({ input: child.stdout, terminal: false }).on('line', (line) => {
            emitLog(`${tag} ${line}`, 'info');
          });

          createInterface({ input: child.stderr, terminal: false }).on('line', (line) => {
            emitLog(`${tag} ${line}`, 'error');
          });

          child.once('error', reject);
          child.once('close', (code) => resolve(code ?? 1));
        })
    )
  );

  return exitCodes.find((code) => code !== 0) ?? 0;
}
