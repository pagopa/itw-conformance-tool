import { spawn, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';

import { testCategories, type TestCategory } from '@itw-conformance-tool/utils';

import { startServiceControlServer } from '../serviceControlServer.js';
import { ServiceSupervisor, type SupervisedService } from '../supervisor.js';
import { findNxRoot } from '../utils/search.js';

export const SERVICE_CONTROL_ENDPOINT_ENV_VAR = 'ITWCT_SERVICE_CONTROL_ENDPOINT';
export const CONFORMANCE_VERBOSE_ENV_VAR = 'ITWCT_CONFORMANCE_VERBOSE';

export interface RunConformanceTestsOptions {
  verbose?: boolean;
}

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
  if (category === 'wallet-provider') return ['trust-anchor', 'wallet-provider'];
  return [];
}

/** Configures Vitest for one category, or for the complete conformance matrix. */
export function createConformanceTestEnvironment(
  category: TestCategory | undefined,
  environment: NodeJS.ProcessEnv = process.env,
  isInteractive = process.stdout.isTTY === true,
  controlEndpoint?: string,
  options: RunConformanceTestsOptions = {}
): NodeJS.ProcessEnv {
  const testEnvironment = { ...environment };
  delete testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY;
  delete testEnvironment[SERVICE_CONTROL_ENDPOINT_ENV_VAR];
  delete testEnvironment[CONFORMANCE_VERBOSE_ENV_VAR];

  if (category) {
    testEnvironment.ITWCT_CONFORMANCE_TEST_CATEGORY = category;
  }

  if (controlEndpoint) {
    testEnvironment[SERVICE_CONTROL_ENDPOINT_ENV_VAR] = controlEndpoint;
  }

  if (options.verbose) {
    testEnvironment[CONFORMANCE_VERBOSE_ENV_VAR] = '1';
  } else if (testEnvironment.NODE_OPTIONS?.match(/--(?:inspect|inspect-brk|debug)(?:=|\b)/)) {
    delete testEnvironment.NODE_OPTIONS;
  }

  if (!isInteractive || testEnvironment.FORCE_COLOR !== undefined || testEnvironment.NO_COLOR !== undefined) {
    return testEnvironment;
  }

  return { ...testEnvironment, FORCE_COLOR: '1' };
}

export const VITEST_SHUTDOWN_GRACE_MS = 5_000;

/**
 * Terminates the Vitest process tree. On POSIX platforms the child is
 * spawned as the leader of its own process group (see `runVitest`), so
 * signaling the negated pid reaches `pnpm`, `vitest`, and any descendants
 * they spawned. Windows lacks an equivalent primitive here, matching the
 * limitation already accepted in `ServiceSupervisor.kill`.
 */
function killVitestTree(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    // The process may have already exited between the state check and kill.
  }
}

export function runVitest(args: string[], cwd: string, env: NodeJS.ProcessEnv, signal?: AbortSignal): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('pnpm', args, {
      cwd,
      env,
      shell: process.platform === 'win32',
      stdio: 'inherit',
      detached: process.platform !== 'win32'
    });

    let escalationTimer: NodeJS.Timeout | undefined;

    const onAbort = (): void => {
      killVitestTree(child, 'SIGTERM');
      escalationTimer = setTimeout(() => killVitestTree(child, 'SIGKILL'), VITEST_SHUTDOWN_GRACE_MS);
      escalationTimer.unref();
    };

    const cleanup = (): void => {
      clearTimeout(escalationTimer);
      signal?.removeEventListener('abort', onAbort);
    };

    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }

    child.once('error', (error) => {
      cleanup();
      reject(error);
    });
    child.once('exit', (code) => {
      cleanup();
      resolve(code ?? 1);
    });
  });
}

/** Runs one conformance category, or the complete matrix, with the CLI owning local services. */
export async function runConformanceTests(
  category?: TestCategory,
  options: RunConformanceTestsOptions = {}
): Promise<number> {
  const nxRootPath = findNxRoot();
  const serviceEnvironment = createConformanceTestEnvironment(
    category,
    process.env,
    process.stdout.isTTY === true,
    undefined,
    options
  );
  const supervisor = new ServiceSupervisor({ cwd: nxRootPath, env: serviceEnvironment });
  const abortController = new AbortController();
  let cancellationRequested = false;
  let stopPromise: Promise<void> | undefined;
  const stop = (): void => {
    cancellationRequested = true;
    // eslint-disable-next-line no-console
    console.log('\nCancellation requested. Stopping local services...');
    abortController.abort();
    stopPromise ??= supervisor.stopAll();
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
      createConformanceTestEnvironment(
        category,
        process.env,
        process.stdout.isTTY === true,
        controlServer.endpoint,
        options
      ),
      abortController.signal
    );
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    await controlServer?.close();
    await (stopPromise ?? supervisor.stopAll());
    if (cancellationRequested) {
      // eslint-disable-next-line no-console
      console.log('Local services stopped.');
    }
  }
}
