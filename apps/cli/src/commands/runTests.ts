import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { findNxRoot } from '../utils/search.js';
import { testCategoryFilters, type TestCategory } from './testCategories.js';

/** Builds the Vitest arguments for a selected conformance test category. */
export function buildConformanceTestArgs(category: TestCategory, nxRootPath: string): string[] {
  const configFile = 'vitest.conformance-test.config.mts';

  return ['vitest', 'run', '--config', join(nxRootPath, configFile), testCategoryFilters[category]];
}

/**
 * Vitest runs tests in child processes that do not report a TTY. Preserve colors
 * for an interactive CLI invocation without overriding explicit user preferences.
 */
export function createConformanceTestEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
  isInteractive = process.stdout.isTTY === true
): NodeJS.ProcessEnv {
  if (!isInteractive || environment.FORCE_COLOR !== undefined || environment.NO_COLOR !== undefined) return environment;

  return { ...environment, FORCE_COLOR: '1' };
}

/**
 * Test command to orchestrate and execute a selected conformance test category.
 */
export function runConformanceTests(category: TestCategory): number {
  const nxRootPath = findNxRoot();
  const vitestArgs = buildConformanceTestArgs(category, nxRootPath);

  const result = spawnSync('pnpm', vitestArgs, {
    cwd: nxRootPath,
    env: createConformanceTestEnvironment(),
    shell: process.platform === 'win32',
    stdio: 'inherit'
  });

  return result.status ?? 1;
}
