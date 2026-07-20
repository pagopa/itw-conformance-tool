import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { defineConfig } from 'vitest/config';

const packageRoot = import.meta.dirname;

const builtReporterPath = resolve(packageRoot, 'packages/conformance/dist/reporters/vitest-conformance-reporter.js');
const sourceReporterPath = './packages/conformance/src/reporters/vitest-conformance-reporter.ts';
const reporterModule = await import(sourceReporterPath).catch(async () => {
  if (!existsSync(builtReporterPath)) {
    throw new Error('Unable to load VitestConformanceReporter from source or dist');
  }
  return import(pathToFileURL(builtReporterPath).href);
});
const { VitestConformanceReporter } = reporterModule;

export function createTestConfig() {
  return defineConfig(() => ({
    root: packageRoot,
    cacheDir: './node_modules/.vite/packages/conformance-test',
    resolve: {
      alias: {
        '@itw-conformance-tool/conformance': resolve(packageRoot, './packages/conformance/src/index.ts'),
        '@itw-conformance-tool/crypto': resolve(packageRoot, './packages/crypto/src/index.ts'),
        '@itw-conformance-tool/database': resolve(packageRoot, './packages/database/src/index.ts'),
        '@itw-conformance-tool/rp': resolve(packageRoot, './packages/rp/src/index.ts')
      }
    },
    test: {
      name: '@itw-conformance-tool/conformance-test',
      watch: false,
      passWithNoTests: true,
      globals: true,
      environment: 'node',
      include: [
        'packages/conformance/src/tests/matrix/**/*.test.ts',
        'apps/itw-relying-party/src/tests/matrix/**/*.test.ts'
      ],
      reporters: ['dot', new VitestConformanceReporter('conformance-test')],
      // node:sqlite requires --experimental-sqlite on Node.js 22.
      pool: 'forks',
      forks: {
        execArgv: ['--experimental-sqlite']
      }
    }
  }));
}
