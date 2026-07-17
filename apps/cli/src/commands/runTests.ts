import { spawn } from 'node:child_process';
import { join } from 'node:path';

import { ServiceSupervisor, type SupervisedService } from '../services/serviceSupervisor.js';
import { findNxRoot } from '../utils/search.js';
import { testCategoryFilters, type TestCategory } from './testCategories.js';

/** Builds the Vitest arguments for a selected conformance test category. */
export function buildConformanceTestArgs(category: TestCategory, nxRootPath: string): string[] {
  return [
    'vitest',
    'run',
    '--config',
    join(nxRootPath, 'vitest.conformance-test.config.mts'),
    testCategoryFilters[category]
  ];
}

export function requiredServicesForCategory(category: TestCategory): SupervisedService[] {
  if (category === 'issuance') return ['trust-anchor', 'credential-issuer'];
  if (category === 'presentation') return ['trust-anchor', 'relying-party'];
  if (category === 'wallet-instance') return ['trust-anchor', 'credential-issuer', 'relying-party'];
  return [];
}

/** Preserves colours for an interactive CLI invocation without overriding user preferences. */
export function createConformanceTestEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
  isInteractive = process.stdout.isTTY === true
): NodeJS.ProcessEnv {
  if (!isInteractive || environment.FORCE_COLOR !== undefined || environment.NO_COLOR !== undefined) return environment;
  return { ...environment, FORCE_COLOR: '1' };
}

function runVitest(args: string[], cwd: string, env: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('pnpm', args, { cwd, env, shell: process.platform === 'win32', stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code) => resolve(code ?? 1));
  });
}

/** Runs a category with the CLI as the sole owner of required local services. */
export async function runConformanceTests(category: TestCategory, configFilePath: string): Promise<number> {
  const nxRootPath = findNxRoot();
  const supervisor = new ServiceSupervisor({ configFilePath, cwd: nxRootPath });
  const stop = (): void => {
    void supervisor.stopAll();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);

  try {
    await supervisor.start(requiredServicesForCategory(category));
    return await runVitest(
      buildConformanceTestArgs(category, nxRootPath),
      nxRootPath,
      createConformanceTestEnvironment()
    );
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    await supervisor.stopAll();
  }
}
