import { spawn } from 'node:child_process';
import { join } from 'node:path';

import { findNxRoot } from '../utils/search.js';

import type { EmitLog } from '../types/types.js';

/** Test command to orchestrate and execute conformance tests.
 *
 * @param emitLog Logger function for console output
 * @returns Promise<void>
 */
export async function test(env: NodeJS.ProcessEnv, emitLog: EmitLog): Promise<void> {
  const nxRootPath = findNxRoot();
  const configFile = 'vitest.conformance-test.config.mts';

  const vitestArgs = ['vitest', 'run', '--config', join(nxRootPath, configFile)];

  const exitCode = await new Promise<number>((resolve, reject) => {
    const child = spawn('pnpm', vitestArgs, {
      cwd: nxRootPath,
      env,
      stdio: 'inherit'
    });

    child.on('error', reject);
    child.on('close', (code) => resolve(code ?? 1));
  });

  if (exitCode !== 0) {
    throw new Error(`Conformance tests failed with exit code ${exitCode}`);
  }

  emitLog('Conformance tests completed', 'info');
}
