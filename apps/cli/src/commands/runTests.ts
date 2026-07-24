import { spawn } from 'node:child_process';
import { join } from 'node:path';

import { testCategories, type TestCategory } from '@itw-conformance-tool/utils';

import { startServiceControlServer } from '../serviceControlServer.js';
import { ServiceSupervisor, type SupervisedService } from '../supervisor.js';
import { findNxRoot } from '../utils/search.js';

export const SERVICE_CONTROL_ENDPOINT_ENV_VAR = 'ITWCT_SERVICE_CONTROL_ENDPOINT';

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
  if (category === 'wallet-instance') return ['trust-anchor', 'wallet-provider'];
  return [];
}

/** Configures Vitest for one category, or for the complete conformance matrix. */
export function createConformanceTestEnvironment(
  category: TestCategory | undefined,
  environment: NodeJS.ProcessEnv = process.env,
  isInteractive = process.stdout.isTTY === true,
  controlEndpoint?: string
): NodeJS.ProcessEnv {
  const testEnvironment = { ...environment };
  delete testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY;
  delete testEnvironment[SERVICE_CONTROL_ENDPOINT_ENV_VAR];

  if (category) {
    testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY = category;
  }

  if (controlEndpoint) {
    testEnvironment[SERVICE_CONTROL_ENDPOINT_ENV_VAR] = controlEndpoint;
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

  let controlServer: Awaited<ReturnType<typeof startServiceControlServer>> | undefined;

  try {
    await supervisor.start(
      category
        ? requiredServicesForCategory(category)
        : ['trust-anchor', 'credential-issuer', 'relying-party', 'wallet-provider']
    );
    controlServer = await startServiceControlServer({ supervisor });
    return await runVitest(
      buildConformanceTestArgs(category, nxRootPath),
      nxRootPath,
      createConformanceTestEnvironment(category, process.env, process.stdout.isTTY === true, controlServer.endpoint)
    );
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    await controlServer?.close();
    await supervisor.stopAll();
  }
}
