import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { findNxRoot } from '../utils/search.js';

/**
 * Test command to orchestrate and execute conformance tests.
 */
export async function runConformanceTests(env: NodeJS.ProcessEnv): Promise<void> {
  const nxRootPath = findNxRoot();
  const configFile = 'vitest.conformance-test.config.mts';
  const vitestArgs = ['vitest', 'run', '--config', join(nxRootPath, configFile)];

  const result = spawnSync('pnpm', vitestArgs, {
    cwd: nxRootPath,
    env,
    stdio: 'inherit'
  });

  process.exit(result.status ?? 1);
}
