import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';

import { searchNx } from '../utils/search.js';

import type { EmitLog, LogLevel, ServiceProcess } from '../types/types.js';
import type { Readable } from 'node:stream';

const ansiEscapePattern = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, 'g');
const serviceLogPattern =
  /^(?:\[[^\]]+\]\s+(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\b|\{.*"level":(?:10|20|30|40|50|60)\b.*"msg":)/;

function stripAnsi(line: string): string {
  return line.replace(ansiEscapePattern, '');
}

function isServiceLog(line: string): boolean {
  return serviceLogPattern.test(stripAnsi(line));
}

function pipeServiceLogs(stream: Readable, prefix: string, level: LogLevel, emitLog: EmitLog): void {
  createInterface({ input: stream, terminal: false }).on('line', (line) => {
    if (!isServiceLog(line)) return;

    emitLog(`[${prefix}] ${line}`, level);
  });
}

/** Spawns a single service process and pipes only application logs through the
 * provided logger with a `[prefix]` tag on each line.
 *
 * @param nxCliPath - Absolute path to the Nx CLI entry point.
 * @param service - The service descriptor (prefix + Nx arguments).
 * @param rootPath - The working directory for the child process.
 * @param emitLog - Logger function used to emit prefixed output lines.
 * @param settle - Callback invoked when the process exits or errors, with its exit code.
 * @returns The spawned ChildProcess instance.
 */
function spawnService(
  nxCliPath: string,
  { prefix, nxArgs }: ServiceProcess,
  rootPath: string,
  emitLog: EmitLog,
  settle: (code: number) => void
): ChildProcess {
  const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
    stdio: ['inherit', 'pipe', 'pipe'],
    cwd: rootPath
  });

  pipeServiceLogs(child.stdout, prefix, 'info', emitLog);
  pipeServiceLogs(child.stderr, prefix, 'error', emitLog);

  child.once('error', (err) => {
    emitLog(`[${prefix}] process error: ${err.message}`, 'error');
    settle(1);
  });

  child.once('close', (code) => {
    settle(code ?? 1);
  });

  return child;
}

/** Runs the specified Nx CLI commands for the selected services,
 * streaming only issuer/relying-party application logs in real time.
 *
 * Resolves as soon as any child exits with a non-zero code (killing the
 * remaining children) or when all children exit cleanly with code 0.
 *
 * @param rootPath - The root directory of the project.
 * @param services - The list of service processes to start.
 * @param emitLog - Logger function used to emit prefixed output lines.
 * @returns A promise that resolves with the first non-zero exit code, or 0 if all succeed.
 */
export async function runCommands(rootPath: string, services: ServiceProcess[], emitLog: EmitLog): Promise<number> {
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
      const child = spawnService(nxCliPath, service, rootPath, emitLog, (code) => {
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
