import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';

import { searchNx } from '../utils/search.js';

import type { EmitLog, ServiceProcess } from '../types/types.js';

/** Spawns a single service process and pipes its stdout/stderr through the
 * provided logger with a `[prefix]` tag on each line.
 *
 * @param nxCliPath - Absolute path to the Nx CLI entry point.
 * @param service - The service descriptor (prefix + Nx arguments).
 * @param rootPath - The working directory for the child process.
 * @param env - Environment variables for the child process.
 * @param emitLog - Logger function used to emit prefixed output lines.
 * @param settle - Callback invoked when the process exits or errors, with its exit code.
 * @returns The spawned ChildProcess instance.
 */
function spawnService(
  nxCliPath: string,
  { prefix, nxArgs }: ServiceProcess,
  rootPath: string,
  env: NodeJS.ProcessEnv,
  emitLog: EmitLog,
  settle: (code: number) => void
): ChildProcess {
  const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
    stdio: ['inherit', 'pipe', 'pipe'],
    cwd: rootPath,
    env
  });

  const tag = `[${prefix}]`;

  createInterface({ input: child.stdout, terminal: false }).on('line', (line) => {
    const message = line.length > 0 ? `${tag} ${line}` : tag;
    emitLog(message, 'info');
  });

  createInterface({ input: child.stderr, terminal: false }).on('line', (line) => {
    const message = line.length > 0 ? `${tag} ${line}` : tag;
    emitLog(message, 'error');
  });

  child.once('error', (err) => {
    emitLog(`${tag} process error: ${err.message}`, 'error');
    settle(1);
  });

  child.once('close', (code) => {
    settle(code ?? 1);
  });

  return child;
}

/** Runs the specified Nx CLI commands for the selected services,
 * streaming their output in real-time.
 *
 * Resolves as soon as any child exits with a non-zero code (killing the
 * remaining children) or when all children exit cleanly with code 0.
 *
 * @param rootPath - The root directory of the project.
 * @param services - The list of service processes to start.
 * @param env - The environment variables to use for the child processes.
 * @param emitLog - Logger function used to emit prefixed output lines.
 * @returns A promise that resolves with the first non-zero exit code, or 0 if all succeed.
 */
export async function runCommands(
  rootPath: string,
  services: ServiceProcess[],
  env: NodeJS.ProcessEnv,
  emitLog: EmitLog
): Promise<number> {
  const nxCliPath = searchNx(rootPath);
  const children: ChildProcess[] = [];

  return new Promise<number>((resolve) => {
    let settled = false;
    let cleanExits = 0;

    function settle(code: number): void {
      if (settled) return;
      settled = true;
      if (code !== 0) {
        for (const child of children) {
          child.kill();
        }
      }
      resolve(code);
    }

    for (const service of services) {
      const child = spawnService(nxCliPath, service, rootPath, env, emitLog, (code) => {
        if (code !== 0) {
          settle(code);
          return;
        }
        cleanExits += 1;
        if (cleanExits === services.length) {
          settle(0);
        }
      });
      children.push(child);
    }
  });
}
