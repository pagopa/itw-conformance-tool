import { spawn } from 'node:child_process';
import { join } from 'node:path';

import { testCategories, type TestCategory } from '@itw-conformance-tool/utils';

import { ServiceSupervisor, type SupervisedService } from '../supervisor.js';
import { findNxRoot } from '../utils/search.js';

/** Builds the Vitest arguments for one category, or all conformance matrix tests. */
export function buildConformanceTestArgs(category: TestCategory | undefined, nxRootPath: string): string[] {
  const args = ['vitest', 'run', '--config', join(nxRootPath, 'vitest.conformance.config.mts')];
  if (category) {
    args.push(testCategories[category].fileName);
  }
  return args;
}

export function requiredServicesForCategory(category: TestCategory): SupervisedService[] {
  if (category === 'issuance') return ['trust-anchor', 'credential-issuer'];
  if (category === 'presentation') return ['trust-anchor', 'relying-party'];
  if (category === 'wallet-instance') return ['trust-anchor', 'credential-issuer', 'relying-party'];
  return [];
}

/** Configures Vitest for one category, or for the complete conformance matrix. */
export function createConformanceTestEnvironment(
  category: TestCategory | undefined,
  environment: NodeJS.ProcessEnv = process.env,
  isInteractive = process.stdout.isTTY === true
): NodeJS.ProcessEnv {
  const testEnvironment = { ...environment };
  delete testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY;

  if (category) {
    testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY = category;
  }

  if (!isInteractive || testEnvironment.FORCE_COLOR !== undefined || testEnvironment.NO_COLOR !== undefined) {
    return testEnvironment;
  }

  return { ...testEnvironment, FORCE_COLOR: '1' };
}

function runVitest(args: string[], cwd: string, env: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('pnpm', args, { cwd, env, shell: process.platform === 'win32', stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code) => resolve(code ?? 1));
  });
}

/** Runs one conformance category, or the complete matrix, with the CLI owning local services. */
export async function runConformanceTests(category?: TestCategory): Promise<number> {
  const nxRootPath = findNxRoot();
  const supervisor = new ServiceSupervisor({ cwd: nxRootPath });
  const stop = (): void => {
    void supervisor.stopAll();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);

  try {
    await supervisor.start(
      category ? requiredServicesForCategory(category) : ['trust-anchor', 'credential-issuer', 'relying-party']
    );
    return await runVitest(
      buildConformanceTestArgs(category, nxRootPath),
      nxRootPath,
      createConformanceTestEnvironment(category)
    );
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    await supervisor.stopAll();
  }
}
