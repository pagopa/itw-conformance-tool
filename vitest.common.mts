import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { defineConfig } from 'vitest/config';

const packageRoot = import.meta.dirname;

const builtReporterPath = resolve(packageRoot, 'packages/conformance/dist/reporters/vitest-conformance-reporter.js');
const reporterModule = existsSync(builtReporterPath)
  ? await import(pathToFileURL(builtReporterPath).href)
  : await import('./packages/conformance/src/reporters/vitest-conformance-reporter.ts');
const { VitestConformanceReporter } = reporterModule;

type TestConfigType = 'issuance' | 'presentation' | 'wallet-provider-backend';

type TestConfigOptions = {
  cacheDir: string;
  coverageReportsDirectory?: string;
  exclude?: string[];
  include: string[];
  name: string;
  reporterType?: TestConfigType;
};

const testConfigs: Record<TestConfigType, TestConfigOptions> = {
  issuance: {
    cacheDir: './node_modules/.vite/packages/conformance-issuance',
    include: ['packages/conformance/src/tests/**/*.issuance.{test,spec}.ts'],
    name: '@itw-conformance-tool/conformance-issuance',
    reporterType: 'issuance'
  },
  presentation: {
    cacheDir: './node_modules/.vite/packages/conformance-presentation',
    include: ['packages/conformance/src/tests/**/*.presentation.{test,spec}.ts'],
    name: '@itw-conformance-tool/conformance-presentation',
    reporterType: 'presentation'
  },
  'wallet-provider-backend': {
    cacheDir: './node_modules/.vite/packages/conformance-wallet-provider-backend',
    include: ['packages/conformance/src/tests/matrix/wallet-provider-backend.test.ts'],
    name: '@itw-conformance-tool/conformance-wallet-provider-backend',
    reporterType: 'wallet-provider-backend'
  }
};

export function createTestConfig(testType: TestConfigType) {
  const options = testConfigs[testType];
  const reporters = options.reporterType ? ['dot', new VitestConformanceReporter(options.reporterType)] : ['default'];

  return defineConfig(() => ({
    root: packageRoot,
    cacheDir: options.cacheDir,
    resolve: {
      alias: {
        '@itw-conformance-tool/database': resolve(packageRoot, './packages/database/src/index.ts')
      }
    },
    test: {
      name: options.name,
      watch: false,
      passWithNoTests: true,
      globals: true,
      environment: 'node',
      include: options.include,
      exclude: options.exclude,
      reporters,
      // node:sqlite requires --experimental-sqlite on Node.js 22.
      pool: 'forks',
      forks: {
        execArgv: ['--experimental-sqlite']
      },
      ...(options.coverageReportsDirectory
        ? {
            coverage: {
              reportsDirectory: options.coverageReportsDirectory,
              provider: 'v8' as const
            }
          }
        : {})
    }
  }));
}
